package org.example.testdigitalsignature.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.testdigitalsignature.service.PdfSigningService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/pdf")
@RequiredArgsConstructor
public class PdfSignatureController {

    private final PdfSigningService pdfSigningService;

    /**
     * Bước 1: Chuẩn bị tài liệu và tạo hash
     */
    @PostMapping("/prepare")
    public ResponseEntity<?> prepareDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "page", required = false, defaultValue = "1") Integer page,
            @RequestParam(value = "x", required = false, defaultValue = "400") Float x,
            @RequestParam(value = "y", required = false, defaultValue = "100") Float y,
            @RequestParam(value = "width", required = false, defaultValue = "200") Float width,
            @RequestParam(value = "height", required = false, defaultValue = "50") Float height,
            @RequestParam(value = "signatureImage", required = false) MultipartFile signatureImage,
            @RequestParam(value = "signerName", required = false) String signerName) {

        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", true,
                        "message", "Không có file được tải lên"
                ));
            }

            // Kiểm tra loại file
            if (!file.getContentType().equals("application/pdf")) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", true,
                        "message", "Chỉ hỗ trợ file PDF"
                ));
            }

            // Kiểm tra hình ảnh chữ ký nếu có
            if (signatureImage != null && !signatureImage.isEmpty()) {
                String contentType = signatureImage.getContentType();
                if (contentType == null || !(contentType.equals("image/jpeg") ||
                        contentType.equals("image/png") ||
                        contentType.equals("image/gif"))) {
                    return ResponseEntity.badRequest().body(Map.of(
                            "error", true,
                            "message", "Ảnh chữ ký phải có định dạng JPG, PNG hoặc GIF"
                    ));
                }
            }

            String hashWithSessionId = pdfSigningService.preparePdfForSigning(
                    file, page, x, y, width, height, signatureImage, signerName);
            String[] parts = hashWithSessionId.split(":");
            String hash = parts[0];
            String sessionId = parts[1];

            Map<String, Object> response = new HashMap<>();
            response.put("hash", hash);
            response.put("sessionId", sessionId);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "error", true,
                    "message", "Lỗi khi chuẩn bị file: " + e.getMessage()
            ));
        }
    }

    /**
     * Bước 2: Tạo chữ ký từ hash và file P12
     */
    @PostMapping("/create-signature")
    public ResponseEntity<?> createSignature(
            @RequestParam("p12File") MultipartFile p12File,
            @RequestParam("password") String password,
            @RequestParam("sessionId") String sessionId) {

        try {
            if (p12File.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", true,
                        "message", "Không có file P12/PFX được tải lên"
                ));
            }

            byte[] signature = pdfSigningService.createSignature(p12File, password, sessionId);
            String base64Signature = java.util.Base64.getEncoder().encodeToString(signature);

            Map<String, Object> response = new HashMap<>();
            response.put("signature", base64Signature);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "error", true,
                    "message", "Lỗi khi tạo chữ ký: " + e.getMessage()
            ));
        }
    }

    /**
     * Bước 3: Hoàn thành ký tài liệu
     */
    @PostMapping("/complete")
    public ResponseEntity<?> completeSigning(
            @RequestParam("signature") String signature,
            @RequestParam("sessionId") String sessionId) {

        try {
            byte[] signedPdf = pdfSigningService.completeSigning(
                    java.util.Base64.getDecoder().decode(signature),
                    sessionId
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "signed.pdf");

            return new ResponseEntity<>(signedPdf, headers, HttpStatus.OK);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "error", true,
                    "message", "Lỗi khi hoàn thành ký: " + e.getMessage()
            ));
        }
    }

    /**
     * API để kiểm tra trạng thái của dịch vụ
     */
    @GetMapping("/status")
    public ResponseEntity<?> getServiceStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "online");
        status.put("message", "Dịch vụ ký số PDF đang hoạt động");
        status.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(status);
    }

    /**
     * API để xem danh sách các phiên ký hiện tại (chỉ dùng cho mục đích debug)
     */
    @GetMapping("/sessions")
    public ResponseEntity<?> getActiveSessions() {
        Map<String, Object> response = new HashMap<>();
        response.put("count", pdfSigningService.getActiveSessionCount());

        return ResponseEntity.ok(response);
    }
}