package org.example.testdigitalsignature.service;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.testdigitalsignature.common.SigningSession;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PdfSigningService {

    static {
        // Đăng ký BouncyCastle provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // Map lưu trữ các phiên ký
    private final Map<String, SigningSession> signingSessions = new ConcurrentHashMap<>();

    // Thời gian hết hạn của phiên (phút)
    private static final int SESSION_TIMEOUT_MINUTES = 30;

    /**
     * Xóa các phiên ký đã hết hạn
     */
    public void cleanupExpiredSessions() {
        Date now = new Date();
        long expirationTimeMillis = SESSION_TIMEOUT_MINUTES * 60 * 1000L;

        signingSessions.entrySet().removeIf(entry -> {
            Date creationTime = entry.getValue().getTimestamp();
            return (now.getTime() - creationTime.getTime()) > expirationTimeMillis;
        });
    }

    /**
     * Bước 1: Chuẩn bị tài liệu và tạo hash (data to be signed) - KHÔNG ký lên PDF
     */
    public String preparePdfForSigning(
            MultipartFile file,
            int pageNumber,
            float x,
            float y,
            float width,
            float height,
            MultipartFile signatureImage,
            String signerName) throws Exception {

        // Tạo ID phiên và tên trường chữ ký
        String sessionId = UUID.randomUUID().toString();
        String signatureField = "Signature_" + sessionId.replaceAll("-", "");

        // Tạo PDF với trường chữ ký
        byte[] pdfWithSignatureField = createPdfWithSignatureField(
                file, signatureField, pageNumber, x, y, width, height
        );

        // Tạo hash (data to be signed) nhưng KHÔNG ký lên PDF
        byte[] hash;
        try (
            ByteArrayInputStream bais = new ByteArrayInputStream(pdfWithSignatureField);
            ByteArrayOutputStream baos = new ByteArrayOutputStream()
        ) {
            PdfReader reader = new PdfReader(bais);
            PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties().useAppendMode());
            signer.setFieldName(signatureField);

            // Thiết lập appearance (chỉ để preview, không ảnh hưởng đến hash)
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            if (signatureImage != null && !signatureImage.isEmpty()) {
                ImageData signatureImageData = ImageDataFactory.create(signatureImage.getBytes());
                appearance.setSignatureGraphic(signatureImageData);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }
            if (signerName != null && !signerName.trim().isEmpty()) {
                String text = "Digitally signed by: " + signerName + "\n" +
                        "Date: " + new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(new Date());
                appearance.setLayer2Text(text);
            }

            // Tạo container giả để lấy data to be signed
            DigestSignatureContainer container = new DigestSignatureContainer(DigestAlgorithms.SHA256);
            signer.signExternalContainer(container, 8192);
            hash = container.getHash();
        }

        // Lưu phiên với PDF gốc (chỉ có trường ký, chưa có chữ ký)
        SigningSession session = new SigningSession(pdfWithSignatureField, hash, signatureField);
        if (signatureImage != null && !signatureImage.isEmpty()) {
            session.setSignatureImage(signatureImage.getBytes());
        }
        if (signerName != null && !signerName.trim().isEmpty()) {
            session.setSignerName(signerName);
        }
        signingSessions.put(sessionId, session);

        return Base64.getEncoder().encodeToString(hash) + ":" + sessionId;
    }

    /**
     * Bước 2: Tạo chữ ký từ hash và file P12
     */
    public byte[] createSignature(MultipartFile p12File, String password, String sessionId) throws Exception {
        // Kiểm tra phiên
        if (!signingSessions.containsKey(sessionId)) {
            throw new IllegalArgumentException("Phiên ký không tồn tại hoặc đã hết hạn");
        }

        SigningSession session = signingSessions.get(sessionId);

        // Đọc chứng chỉ P12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(p12File.getInputStream(), password.toCharArray());

        String alias = null;
        for (var aliases = ks.aliases(); aliases.hasMoreElements(); ) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                alias = a;
                break;
            }
        }
        if (alias == null) {
            throw new IllegalArgumentException("Không tìm thấy chứng chỉ hợp lệ trong file P12");
        }

        // Lấy private key và chứng chỉ
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        // Tạo container chữ ký với thuật toán SHA-256 và chứng chỉ chuỗi
        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);
        
        // Tạo chữ ký PKCS#7 với chứng chỉ chuỗi
        byte[] hash = session.getHash();
        byte[] signature = pks.sign(hash);
        
        // Lưu chứng chỉ chuỗi vào session để sử dụng trong bước hoàn thành
        session.setCertificateChain(chain);

        return signature;
    }

    /**
     * Bước 3: Hoàn thành ký tài liệu (chỉ ký lên PDF gốc với trường ký)
     */
    public byte[] completeSigning(byte[] signature, String sessionId) throws Exception {
        // Kiểm tra phiên
        if (!signingSessions.containsKey(sessionId)) {
            throw new IllegalArgumentException("Phiên ký không tồn tại hoặc đã hết hạn");
        }

        SigningSession session = signingSessions.get(sessionId);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(session.getTempPdf())) {
            PdfReader reader = new PdfReader(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties().useAppendMode());
            signer.setFieldName(session.getFieldName());

            // Thiết lập appearance
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            signer.setSignDate(new GregorianCalendar());
            if (session.getSignatureImage() != null) {
                ImageData signatureImageData = ImageDataFactory.create(session.getSignatureImage());
                appearance.setSignatureGraphic(signatureImageData);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }
            if (session.getSignerName() != null) {
                String text = "Digitally signed by: " + session.getSignerName() + "\n" +
                        "Date: " + new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(new Date());
                appearance.setLayer2Text(text);
            }

            // Tạo container để chèn chữ ký và chứng chỉ chuỗi
            IExternalSignatureContainer container = new IExternalSignatureContainer() {
                @Override
                public byte[] sign(InputStream data) {
                    return signature;
                }

                @Override
                public void modifySigningDictionary(PdfDictionary signDic) {
                    signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
                    signDic.put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
                    if (session.getCertificateChain() != null) {
                        try {
                            PdfArray certArray = new PdfArray();
                            for (Certificate cert : session.getCertificateChain()) {
                                certArray.add(new PdfString(cert.getEncoded()));
                            }
                            signDic.put(PdfName.Cert, certArray);
                        } catch (Exception e) {
                            throw new RuntimeException("Lỗi khi thêm chứng chỉ chuỗi vào chữ ký", e);
                        }
                    }
                }
            };

            // Chỉ ký lên PDF gốc với trường ký (không bị double-sign)
            signer.signExternalContainer(container, 8192);

            // Xóa phiên sau khi ký
            signingSessions.remove(sessionId);

            return baos.toByteArray();
        }
    }

    /**
     * Tạo PDF với trường chữ ký
     */
    private byte[] createPdfWithSignatureField(
            MultipartFile file,
            String fieldName,
            int pageNumber,
            float x,
            float y,
            float width,
            float height) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfReader reader = new PdfReader(file.getInputStream());
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(baos));

        // Kiểm tra số trang hợp lệ
        if (pageNumber < 1 || pageNumber > pdfDoc.getNumberOfPages()) {
            throw new IllegalArgumentException("Số trang không hợp lệ: " + pageNumber);
        }

        // Tạo trường chữ ký
        PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDoc, true);
        Rectangle rect = new Rectangle(x, y, width, height);
        PdfSignatureFormField field = PdfSignatureFormField.createSignature(pdfDoc, rect);
        field.setFieldName(fieldName);
        field.setPage(pageNumber);
        form.addField(field);

        // Đóng tài liệu
        pdfDoc.close();

        return baos.toByteArray();
    }

    /**
     * Lớp container để tính hash của tài liệu
     */
    @Getter
    private static class DigestSignatureContainer implements IExternalSignatureContainer {
        private final String hashAlgorithm;
        private byte[] hash;

        public DigestSignatureContainer(String hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
        }

        @Override
        public byte[] sign(InputStream data) {
            try {
                // Tính hash của dữ liệu
                MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
                byte[] buf = new byte[8192];
                int n;
                while ((n = data.read(buf)) > 0) {
                    messageDigest.update(buf, 0, n);
                }

                this.hash = messageDigest.digest();

                // Trả về một mảng trống, không phải chữ ký thực
                return new byte[0];
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDic.put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
        }
    }

    /**
     * Lấy số lượng phiên ký hiện tại
     */
    public int getActiveSessionCount() {
        return signingSessions.size();
    }
}