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
import org.example.testdigitalsignature.util.KeyStoreLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.security.*;
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
    private static final int SIGNATURE_ESTIMATION_SIZE = 8192;

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
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("PDF file cannot be null or empty");
        }

        String sessionId = UUID.randomUUID().toString();

        try (PdfReader reader = new PdfReader(file.getInputStream());
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            // Create and configure PDF signer
            PdfSigner signer = createPdfSigner(reader, baos);

            // Configure appearance for the signature
            configureSignatureAppearance(signer);

            // Prepare for external signing
            PreSignExternalSignatureContainer container = new PreSignExternalSignatureContainer();
            signer.signExternalContainer(container, SIGNATURE_ESTIMATION_SIZE);

            // Generate hash from the data to be signed
            byte[] dataToSign = container.getDataToSign();
            byte[] hash = generateHash(dataToSign);

            // Store session data for later use
            storeSessionData(sessionId, baos, dataToSign);

            // Return data needed for external signing
            String base64Hash = Base64.getEncoder().encodeToString(hash);
            System.out.println(base64Hash);
            return Map.of("sessionId", sessionId, "hash", base64Hash);
        }
    }

    /**
     * Completes the signing process with the externally generated signature.
     *
     * @param sessionId       The session identifier from the preparation phase
     * @param signatureBase64 The Base64-encoded signature
     * @return The signed PDF document as a byte array
     * @throws Exception If an error occurs during signing
     */
    public byte[] submitSignature(String sessionId, String signatureBase64) throws Exception {
        // Retrieve and validate session data
        ByteArrayOutputStream baos = sessionData.get(sessionId);
        if (baos == null) {
            throw new IllegalArgumentException("Invalid or expired sessionId");
        }

        byte[] signature = Base64.getDecoder().decode(signatureBase64);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
             ByteArrayOutputStream signedOutput = new ByteArrayOutputStream()) {

            // Create PDF signer in append mode
            PdfReader reader = new PdfReader(bais);
            PdfSigner signer = new PdfSigner(reader, signedOutput, new StampingProperties().useAppendMode());

            // IMPORTANT: Do NOT set the field name again here
            // The field was already created in prepareSign
            // Setting it again causes the "Field has been already signed" error

            // Complete the signing process with the provided signature
            IExternalSignatureContainer container = new IExternalSignatureContainer() {
                @Override
                public byte[] sign(InputStream data) {
                    return signature;
                }

                @Override
                public void modifySigningDictionary(PdfDictionary signDic) {
                    // No modifications needed
                }
            };

            signer.signExternalContainer(container, 8192);

            // Optional: Clean up session data
            sessionData.remove(sessionId);
            hashStore.remove(sessionId);

            return signedOutput.toByteArray();
        }
    }


    /**
     * Verifies the signatures in a signed PDF document.
     * 
     * @param signedPdf The signed PDF document
     * @return true if all signatures are valid, false otherwise
     * @throws Exception If an error occurs during verification
     */
    public boolean verifySignature(MultipartFile signedPdf) throws Exception {
        if (signedPdf == null || signedPdf.isEmpty()) {
            throw new IllegalArgumentException("Signed PDF file cannot be null or empty");
        }
        
        try (PdfDocument pdfDoc = new PdfDocument(new PdfReader(signedPdf.getInputStream()))) {
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();
            
            if (names.isEmpty()) {
                return false; // No signatures found
            }
            
            for (String name : names) {
                try {
                    PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                    if (pkcs7 == null) {
                        return false; // Couldn't read signature data
                    }
                    
                    // Try to verify the signature, catching any internal errors
                    if (!pkcs7.verifySignatureIntegrityAndAuthenticity()) {
                        return false;
                    }
                } catch (Exception e) {
                    // Log the error for debugging purposes
                    System.err.println("Error verifying signature '" + name + "': " + e.getMessage());
                    return false; // Consider the signature invalid if verification throws an exception
                }
            }
            
            return true; // All signatures are valid
        }
    }


// Helper methods for cleaner implementation

    private PdfSigner createPdfSigner(PdfReader reader, ByteArrayOutputStream outputStream) throws IOException {
        return new PdfSigner(reader, outputStream, new StampingProperties());
    }

    private void configureSignatureAppearance(PdfSigner signer) {
        signer.setFieldName(DEFAULT_SIGNATURE_FIELD_NAME);
        signer.getSignatureAppearance()
                .setReason(DEFAULT_SIGNATURE_REASON)
                .setLocation(DEFAULT_SIGNATURE_LOCATION)
                .setReuseAppearance(false)
                .setPageRect(new Rectangle(640, 70, 150, 80))
                .setPageNumber(1);
    }

    private byte[] generateHash(byte[] dataToSign) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(dataToSign);
    }

    private void storeSessionData(String sessionId, ByteArrayOutputStream baos, byte[] dataToSign) {
        sessionData.put(sessionId, baos);
        hashStore.put(sessionId, dataToSign);
    }

    private void cleanupSessionData(String sessionId) {
        // Optional: remove session data after use to free up memory
        sessionData.remove(sessionId);
        hashStore.remove(sessionId);
    }

    private IExternalSignatureContainer createSignatureContainer(byte[] signature) {
        return new IExternalSignatureContainer() {
            @Override
            public byte[] sign(InputStream data) {
                return signature;
            }

            @Override
            public void modifySigningDictionary(PdfDictionary signDic) {
                // No modifications needed
            }
        };
    }

    private static class PreSignExternalSignatureContainer implements IExternalSignatureContainer {
        private final ByteArrayOutputStream dataToSign = new ByteArrayOutputStream();

        @Override
        public byte[] sign(InputStream is) throws GeneralSecurityException {
            try {
                is.transferTo(dataToSign);
            } catch (IOException e) {
                throw new GeneralSecurityException("Unable to read data to sign", e);
            }
            return new byte[0]; // dummy signature for pre-sign
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            // No modification needed
        }

        public byte[] getDataToSign() {
            return dataToSign.toByteArray();
        }
    }
}