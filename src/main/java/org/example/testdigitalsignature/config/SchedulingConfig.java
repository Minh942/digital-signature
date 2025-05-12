package org.example.testdigitalsignature.config;

import lombok.extern.slf4j.Slf4j;
import org.example.testdigitalsignature.service.PdfSigningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Slf4j
@Configuration
@EnableScheduling
public class SchedulingConfig {
    private final PdfSigningService pdfSigningService;

    @Autowired
    public SchedulingConfig(PdfSigningService pdfSigningService) {
        this.pdfSigningService = pdfSigningService;
    }

    /**
     * Chạy mỗi 15 phút để dọn dẹp các phiên ký hết hạn
     */
    @Scheduled(fixedRate = 15 * 60 * 1000)
    public void cleanUpExpiredSessions() {
        log.info("Clean up expired sessions...");
        pdfSigningService.cleanupExpiredSessions();
    }

}
