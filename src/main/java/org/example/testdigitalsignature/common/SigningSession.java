package org.example.testdigitalsignature.common;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class SigningSession {
    /**
     * PDF tạm thời với trường chữ ký trống
     */
    private final byte[] tempPdf;

    /**
     * Hash của dữ liệu cần ký
     */
    private final byte[] hash;

    /**
     * Tên trường chữ ký trong tài liệu PDF
     */
    private final String fieldName;

    /**
     * Dữ liệu hình ảnh chữ ký (nếu có)
     */
    private byte[] signatureImage;

    /**
     * Tên người ký (nếu có)
     */
    private String signerName;

    /**
     * Thời điểm tạo phiên
     */
    private final Date timestamp;

    /**
     * Constructor cho phiên ký
     *
     * @param tempPdf    Dữ liệu PDF tạm thời với trường chữ ký trống
     * @param hash       Hash của dữ liệu cần ký
     * @param fieldName  Tên trường chữ ký trong PDF
     */
    public SigningSession(byte[] tempPdf, byte[] hash, String fieldName) {
        this.tempPdf = tempPdf;
        this.hash = hash;
        this.fieldName = fieldName;
        this.timestamp = new Date();
    }

}
