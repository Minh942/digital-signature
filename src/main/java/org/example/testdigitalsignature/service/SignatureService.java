package org.example.testdigitalsignature.service;

import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.example.testdigitalsignature.common.ExtendedPdfSigner;
import org.example.testdigitalsignature.util.KeyStoreLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.example.testdigitalsignature.common.Constant.*;

@Service
public class SignatureService {
    private final KeyStoreLoader keyStoreLoader;
    private final Map<String, ByteArrayOutputStream> sessionData = new ConcurrentHashMap<>();
    private final Map<String, byte[]> hashStore = new ConcurrentHashMap<>();

    public SignatureService(KeyStoreLoader keyStoreLoader) {
        this.keyStoreLoader = keyStoreLoader;
    }

    public byte[] signFile(byte[] data, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(keyStoreLoader.getPrivateKey());
        signature.update(data);
        return signature.sign();
    }

    public boolean verifyFileSignature(byte[] data, byte[] signatureBytes, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(keyStoreLoader.getPublicKey());
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public byte[] signPdf(byte[] pdfBytes) throws Exception {
        ByteArrayOutputStream signedPdf = new ByteArrayOutputStream();

        PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
        PdfSigner signer = new PdfSigner(reader, signedPdf, new StampingProperties());
        Certificate[] chain = new Certificate[]{keyStoreLoader.getCertificate()};

        // Chữ ký hiển thị
        Rectangle rect = new Rectangle(107, 60, 150, 80);
        signer.setFieldName(DEFAULT_SIGNATURE_FIELD_NAME);
        configureSignatureAppearance(signer, rect, chain);

        // Chữ ký thật
        PrivateKey privateKey = keyStoreLoader.getPrivateKey();
        IExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, null);
        IExternalDigest digest = new BouncyCastleDigest();

        signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);

        return signedPdf.toByteArray();
    }

    private void configureSignatureAppearance(PdfSigner signer, Rectangle rect, Certificate[] chain) throws IOException, GeneralSecurityException {
        PdfFont fontLarge = PdfFontFactory.createFont("fonts/Roboto-Bold.ttf", PdfEncodings.IDENTITY_H);
        PdfFont fontSmall = PdfFontFactory.createFont("fonts/Roboto-Regular.ttf", PdfEncodings.IDENTITY_H);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();

        appearance.setReason(DEFAULT_SIGNATURE_REASON)
                .setLocation(DEFAULT_SIGNATURE_LOCATION)
                .setPageRect(rect)
                .setPageNumber(1)
                .setReuseAppearance(false)
                .setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION)
                .setCertificate(chain[0]);
    }

    public boolean verifyPdfSignature(byte[] pdfBytes) throws IOException, GeneralSecurityException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(new ByteArrayInputStream(pdfBytes)));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();

        if (names.isEmpty()) return false;

        for (String name : names) {
            PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
            boolean verified = pkcs7.verifySignatureIntegrityAndAuthenticity();
            if (!verified) return false;
        }
        return true;
    }

    public void signPdfWithImage(InputStream input, OutputStream output, InputStream imageStream) throws Exception {
        PdfReader reader = new PdfReader(input);
        PdfSigner signer = new PdfSigner(reader, output, new StampingProperties());

        Rectangle rect = new Rectangle(640, 70, 150, 80);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason(DEFAULT_SIGNATURE_REASON)
                .setLocation(DEFAULT_SIGNATURE_LOCATION)
                .setPageRect(rect)
                .setPageNumber(1)
                .setReuseAppearance(false)
                .setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC); // hình ảnh

        // Đặt hình ảnh chữ ký
        ImageData signatureImage = ImageDataFactory.create(imageStream.readAllBytes());
        appearance.setSignatureGraphic(signatureImage);

        PrivateKey privateKey = keyStoreLoader.getPrivateKey();
        Certificate[] chain = new Certificate[]{keyStoreLoader.getCertificate()};
        IExternalDigest digest = new BouncyCastleDigest();
        IExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, null);

        signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }

    public Map<String, String> prepareSign(MultipartFile file) throws Exception {
        String sessionId = UUID.randomUUID().toString();

        PdfReader reader = new PdfReader(file.getInputStream());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfSigner signer = new PdfSigner(reader, baos, new StampingProperties());

        signer.setFieldName("Signature1");
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason("Pre-sign")
                .setLocation("VN")
                .setReuseAppearance(false)
                .setPageRect(new Rectangle(100, 100, 200, 100))
                .setPageNumber(1);

        byte[] hash = calculateDocumentHash(signer);

        sessionData.put(sessionId, baos);
        hashStore.put(sessionId, hash);

        String base64Hash = Base64.getEncoder().encodeToString(hash);

        return Map.of("sessionId", sessionId, "hash", base64Hash);
    }

    private byte[] calculateDocumentHash(ExtendedPdfSigner signer) throws GeneralSecurityException, IOException {
        IExternalDigest digest = new BouncyCastleDigest();
        InputStream dataToSign = signer.getRangeStream();
        MessageDigest md = digest.getMessageDigest("SHA256");
        return DigestAlgorithms.digest(dataToSign, md);
    }


    public byte[] submitSignature(String sessionId, String signatureBase64) throws Exception {
        ByteArrayOutputStream baos = sessionData.get(sessionId);
        byte[] signature = Base64.getDecoder().decode(signatureBase64);

        if (baos == null) throw new IllegalArgumentException("Invalid sessionId");

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ByteArrayOutputStream signedOutput = new ByteArrayOutputStream();

        PdfSigner signer = new PdfSigner(new PdfReader(bais), signedOutput, new StampingProperties());
        signer.setFieldName("Signature1");

        signer.signExternalContainer(new ExternalSignatureContainer() {
            public byte[] sign(InputStream data) {
                return signature;
            }

            public void modifySigningDictionary(PdfDictionary signDic) {}
        }, 8192);

        return signedOutput.toByteArray();
    }

    public boolean verifySignature(MultipartFile signedPdf) throws Exception {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(signedPdf.getInputStream()));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();

        for (String name : names) {
            PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
            if (!pkcs7.verifySignatureIntegrityAndAuthenticity()) {
                return false;
            }
        }
        return true;
    }
}
