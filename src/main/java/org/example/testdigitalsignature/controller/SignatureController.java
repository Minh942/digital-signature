package org.example.testdigitalsignature.controller;

import org.example.testdigitalsignature.common.MockMultipartFile;
import org.example.testdigitalsignature.service.SignatureService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/signature")
public class SignatureController {
    private final SignatureService signatureService;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    @PostMapping("/sign")
    public ResponseEntity<byte[]> signFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "algorithm", defaultValue = "SHA256withRSA") String algorithm
    ) {
        try {
            byte[] result;
            if (Objects.requireNonNull(file.getOriginalFilename()).toLowerCase().endsWith(".pdf")) {
                result = signatureService.signPdf(file.getBytes());
            } else {
                result = signatureService.signFile(file.getBytes(), algorithm);
            }
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed_output\"")
                    .body(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifyFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "signature", required = false) MultipartFile sigFile,
            @RequestParam(value = "algorithm", defaultValue = "SHA256withRSA") String algorithm
    ) {
        try {
            boolean valid;
            if (Objects.requireNonNull(file.getOriginalFilename()).toLowerCase().endsWith(".pdf")) {
                valid = signatureService.verifyPdfSignature(file.getBytes());
            } else {
                valid = signatureService.verifyFileSignature(file.getBytes(), sigFile.getBytes(), algorithm);
            }
            return ResponseEntity.ok(valid);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @PostMapping(value = "/pdf-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> signPdfWithImage(
            @RequestParam("file") MultipartFile file,
            @RequestParam("image") MultipartFile image
    ) throws Exception {
        ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
        signatureService.signPdfWithImage(file.getInputStream(), signedOut, image.getInputStream());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(signedOut.toByteArray());
    }

    @PostMapping("/remote-signing")
    public ResponseEntity<?> signAndVerify(@RequestParam("file") MultipartFile file) throws Exception {
        // Step 1: Prepare signing
        Map<String, String> result = signatureService.prepareSign(file);
        String sessionId = result.get("sessionId");

        // get signature value from hash and file empty signature


        // Step 2: Submit signature
        // gGhe chuoi signature vao file empty sig
        byte[] signedPdf = signatureService.submitSignature(sessionId, result.get("hash"));

        // Step 3: Verify
        boolean valid = signatureService.verifySignature(new MockMultipartFile("signed.pdf", signedPdf));

        return ResponseEntity.ok(Map.of(
                "sessionId", sessionId,
                "valid", valid,
                "signedPdf", Base64.getEncoder().encodeToString(signedPdf)
        ));
    }
}
