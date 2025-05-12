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
     * Tạo PDF có trường chữ ký ở vị trí được chỉ định
     */
    public byte[] createPdfWithSignatureField(
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
     * Chuẩn bị PDF để ký defer với vị trí chữ ký tùy chỉnh và hình ảnh chữ ký
     */
    public String preparePdfForDeferredSigning(
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

        // Bước 1: Tạo PDF với trường chữ ký tại vị trí được chỉ định
        byte[] pdfWithSignatureField = createPdfWithSignatureField(
                file, signatureField, pageNumber, x, y, width, height
        );

        // Bước 2: Chuẩn bị PDF cho việc ký deferred
        byte[] tempPdf;
        byte[] hash;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(pdfWithSignatureField)) {
            PdfReader reader = new PdfReader(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties().useAppendMode());
            signer.setFieldName(signatureField);

            // Thiết lập appearance cho chữ ký
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

            // Chuẩn bị cho việc ký deferred
            DigestSignatureContainer container = new DigestSignatureContainer(DigestAlgorithms.SHA256);
            signer.signExternalContainer(container, 8192);

            tempPdf = baos.toByteArray();
            hash = container.getHash();
        }

        // Tạo và lưu phiên
        SigningSession session = new SigningSession(tempPdf, hash, signatureField);
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
     * Hoàn thành việc ký với chữ ký PKCS#1 (đã ký bằng thiết bị ngoài)
     */
    public byte[] completeDeferredSigning(byte[] signatureValue, String sessionId) throws Exception {
        // Kiểm tra phiên
        if (!signingSessions.containsKey(sessionId)) {
            throw new IllegalArgumentException("Phiên ký không tồn tại hoặc đã hết hạn");
        }

        SigningSession session = signingSessions.get(sessionId);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(session.getTempPdf())) {
            PdfReader reader = new PdfReader(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // Tạo Container để chèn chữ ký PKCS#1 vào PDF
            ExternalBlankSignatureContainer container = new ExternalBlankSignatureContainer(
                    PdfSigner.CryptoStandard.CADES
            );

            PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties().useAppendMode());
            signer.setFieldName(session.getFieldName());

            // Thiết lập appearance
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();

            // Thêm ngày ký
            signer.setSignDate(new GregorianCalendar());

            // Thêm hình ảnh chữ ký nếu có
            if (session.getSignatureImage() != null) {
                ImageData signatureImageData = ImageDataFactory.create(session.getSignatureImage());
                appearance.setSignatureGraphic(signatureImageData);
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }

            // Thêm thông tin người ký
            if (session.getSignerName() != null) {
                String text = "Digitally signed by: " + session.getSignerName() + "\n" +
                        "Date: " + new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(new Date());
                appearance.setLayer2Text(text);
            }

            // Tạo vùng chữ ký trống
            signer.signExternalContainer(container, 8192);

            // Chèn chữ ký PKCS#1 vào PDF
            byte[] signedPdf = insertSignature(baos.toByteArray(), signatureValue, session.getFieldName());

            // Xóa phiên sau khi ký
            signingSessions.remove(sessionId);

            return signedPdf;
        }
    }

    /**
     * Phương thức tiện ích để chèn chữ ký vào PDF
     */
    private byte[] insertSignature(byte[] pdfBytes, byte[] pkcs1Signature, String fieldName) throws Exception {
        // Tìm vị trí trường chữ ký và thông tin ByteRange trong PDF
        SignatureUtil signatureUtil;
        byte[] signedPdfBytes;

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(pdfBytes);
             PdfReader reader = new PdfReader(inputStream);
             PdfDocument pdfDocument = new PdfDocument(reader)) {

            signatureUtil = new SignatureUtil(pdfDocument);
//            if (!signatureUtil.signatureExists(fieldName)) {
//                throw new IllegalArgumentException("Trường chữ ký '" + fieldName + "' không tồn tại trong tài liệu");
//            }

            // Lấy vị trí của trường chữ ký
            PdfDictionary signatureDict = signatureUtil.getSignatureDictionary(fieldName);
            if (signatureDict == null) {
                throw new IllegalArgumentException("Không thể tìm thấy từ điển chữ ký cho trường '" + fieldName + "'");
            }

            // Lấy ByteRange - xác định vị trí để chèn chữ ký
            PdfArray byteRange = signatureDict.getAsArray(PdfName.ByteRange);
            if (byteRange == null) {
                throw new IllegalArgumentException("Không tìm thấy ByteRange trong từ điển chữ ký");
            }

            // ByteRange có định dạng [a b c d] với:
            // a: vị trí bắt đầu phần 1
            // b: độ dài phần 1
            // c: vị trí bắt đầu phần 2
            // d: độ dài phần 2
            // Phần chữ ký nằm giữa phần 1 và phần 2
            int[] byteRangeArray = new int[byteRange.size()];
            for (int i = 0; i < byteRangeArray.length; i++) {
                byteRangeArray[i] = byteRange.getAsNumber(i).intValue();
            }

            if (byteRangeArray.length != 4) {
                throw new IllegalArgumentException("ByteRange không đúng định dạng, cần có 4 số");
            }

            // Tính toán vị trí và kích thước của vùng chữ ký
            int signatureOffset = byteRangeArray[0] + byteRangeArray[1] + 1; // +1 để bỏ qua ký tự '<'
            int signatureLength = byteRangeArray[2] - signatureOffset - 1;   // -1 để bỏ qua ký tự '>'

            // Tạo hash từ tài liệu bằng cách đọc phần ByteRange
            byte[] documentHash = calculateDocumentHash(pdfBytes, byteRangeArray);

            // Chuyển đổi chữ ký PKCS#1 thành CMS/PKCS#7
            // Đây là phần mà bạn cần triển khai chi tiết với thư viện Bouncy Castle
            // hoặc sử dụng một thư viện khác để đóng gói PKCS#1 thành CMS/PKCS#7
            byte[] cmsSignature = createCmsSignature(pkcs1Signature, documentHash);

            // Chuyển đổi bytes thành hex string (2 ký tự cho mỗi byte)
            String hexSignature = byteArrayToHexString(cmsSignature);
            if (hexSignature.length() > signatureLength) {
                throw new IllegalArgumentException("Chữ ký quá lớn để chèn vào vùng dành riêng (cần <= "
                        + signatureLength + " hex chars, nhưng có "
                        + hexSignature.length() + " hex chars)");
            }

            // Đảm bảo chữ ký đủ độ dài bằng cách thêm các ký tự '0'
            StringBuilder paddedSignature = new StringBuilder(hexSignature);
            while (paddedSignature.length() < signatureLength) {
                paddedSignature.append('0');
            }

            // Tạo tài liệu PDF đã ký
            signedPdfBytes = new byte[pdfBytes.length];
            System.arraycopy(pdfBytes, 0, signedPdfBytes, 0, pdfBytes.length);

            // Chèn chữ ký vào vị trí đúng
            byte[] signatureHexBytes = paddedSignature.toString().getBytes();
            System.arraycopy(
                    signatureHexBytes, 0,
                    signedPdfBytes, signatureOffset,
                    signatureHexBytes.length
            );

            return signedPdfBytes;
        }
    }

    /**
     * Tính toán hash của tài liệu dựa trên ByteRange
     */
    private byte[] calculateDocumentHash(byte[] pdfBytes, int[] byteRange) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        // Cập nhật hash với phần 1 của tài liệu
        messageDigest.update(pdfBytes, byteRange[0], byteRange[1]);

        // Cập nhật hash với phần 2 của tài liệu
        messageDigest.update(pdfBytes, byteRange[2], byteRange[3]);

        return messageDigest.digest();
    }

    /**
     * Tạo chữ ký CMS/PKCS#7 từ chữ ký PKCS#1 và hash của tài liệu
     * Phương thức này cần triển khai với Bouncy Castle hoặc thư viện tương tự
     */
    private byte[] createCmsSignature(byte[] pkcs1Signature, byte[] documentHash) throws Exception {
        // Đây là phần phức tạp nhất và phụ thuộc vào cách thiết bị ngoài cung cấp chữ ký
        // Đối với một số thiết bị, chúng có thể đã cung cấp chữ ký CMS/PKCS#7 hoàn chỉnh
        // và chúng ta chỉ cần truyền lại

        // Đối với trường hợp thiết bị chỉ cung cấp PKCS#1, bạn cần triển khai logic
        // để tạo CMS/PKCS#7 bằng Bouncy Castle. Ví dụ:

        // Giả định pkcs1Signature là chữ ký CMS/PKCS#7 hoàn chỉnh
        return pkcs1Signature;

    /*
    // Nếu cần tạo CMS từ PKCS#1, sử dụng mã như sau:
    try {
        // Tạo certificate chain - giả sử bạn có sẵn
        X509Certificate[] chain = ...; // Cần được cung cấp

        // Tạo CMS SignedData
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        // Thêm chứng chỉ
        JcaCertStore certStore = new JcaCertStore(Arrays.asList(chain));
        generator.addCertificates(certStore);

        // Tạo SignerInfoGenerator từ PKCS#1
        ContentSigner contentSigner = new CustomContentSigner(pkcs1Signature, documentHash);
        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().build())
            .build(contentSigner, chain[0]);

        generator.addSignerInfoGenerator(signerInfoGenerator);

        // Tạo CMS SignedData
        CMSTypedData cmsTypedData = new CMSProcessableByteArray(documentHash);
        CMSSignedData cmsSignedData = generator.generate(cmsTypedData, true);

        return cmsSignedData.getEncoded();
    } catch (Exception e) {
        throw new RuntimeException("Lỗi khi tạo chữ ký CMS: " + e.getMessage(), e);
    }
    */
    }

    /**
     * Chuyển đổi mảng byte thành chuỗi hex
     */
    private String byteArrayToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    /**
     * Ký PDF với chứng chỉ P12, thêm hình ảnh chữ ký nếu có
     */
    public byte[] signDeferredPdfWithP12(MultipartFile p12File, String password, String sessionId) throws Exception {
        // Kiểm tra phiên
        if (!signingSessions.containsKey(sessionId)) {
            throw new IllegalArgumentException("Phiên ký không tồn tại hoặc đã hết hạn");
        }

        SigningSession session = signingSessions.get(sessionId);

        // Đọc chứng chỉ P12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(p12File.getInputStream(), password.toCharArray());

        String alias = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                break;
            }
        }

        if (alias == null) {
            throw new IllegalArgumentException("Không tìm thấy chứng chỉ hợp lệ trong file P12");
        }

        // Lấy private key và chứng chỉ
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        // Tạo container chữ ký với thuật toán SHA-256
        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, BouncyCastleProvider.PROVIDER_NAME);

        // Ký hash với private key
        byte[] signature = pks.sign(session.getHash());

        // Hoàn thành việc ký
        try (ByteArrayInputStream bais = new ByteArrayInputStream(session.getTempPdf())) {
            PdfReader reader = new PdfReader(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties().useAppendMode());
            signer.setFieldName(session.getFieldName());

            // Chèn chữ ký vào PDF
            byte[] signedPdf = insertSignature(baos.toByteArray(), signature, session.getFieldName());

            // Xóa phiên sau khi ký
            signingSessions.remove(sessionId);

            return signedPdf;
        }
    }

    /**
     * Lấy số lượng phiên ký hiện tại
     */
    public int getActiveSessionCount() {
        return signingSessions.size();
    }

    /**
     * Lớp container để tính hash của tài liệu
     */
    private static class DigestSignatureContainer implements IExternalSignatureContainer {
        private final String hashAlgorithm;
        @Getter
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
     * Lớp container để chèn chữ ký PKCS#1 vào PDF
     */
    private static class ExternalBlankSignatureContainer implements IExternalSignatureContainer {
        private final PdfName filter;
        private final PdfName subFilter;

        public ExternalBlankSignatureContainer(PdfSigner.CryptoStandard sigtype) {

            switch (sigtype) {
                case CMS:
                    this.filter = PdfName.Adobe_PPKLite;
                    this.subFilter = PdfName.Adbe_pkcs7_detached;
                    break;
                case CADES:
                    this.filter = PdfName.Adobe_PPKLite;
                    this.subFilter = PdfName.ETSI_CAdES_DETACHED;
                    break;
                default:
                    throw new IllegalArgumentException("Không hỗ trợ loại chữ ký: " + sigtype);
            }
        }

        @Override
        public byte[] sign(InputStream data) {
            // Đơn giản trả về một mảng trống, vì ta sẽ chèn chữ ký sau
            return new byte[0];
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.put(PdfName.Filter, filter);
            signDic.put(PdfName.SubFilter, subFilter);
        }
    }
}