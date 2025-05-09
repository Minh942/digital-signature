package org.example.testdigitalsignature.common;

import org.springframework.http.MediaType;

public class MockMultipartFile extends ByteArrayMultipartFile {
    public MockMultipartFile(String name, byte[] content) {
        super(name, name, MediaType.APPLICATION_PDF_VALUE, content);
    }
}
