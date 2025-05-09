package org.example.testdigitalsignature.common;

import lombok.Getter;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

public abstract class ByteArrayMultipartFile implements MultipartFile {
    @Getter
    private final String name;
    @Getter
    private final String originalFilename;
    @Getter
    private final String contentType;
    private final byte[] content;

    public ByteArrayMultipartFile(String name, String originalFilename, String contentType, byte[] content) {
        this.name = name;
        this.originalFilename = originalFilename;
        this.contentType = contentType;
        this.content = content;
    }

    public boolean isEmpty() { return content.length == 0; }
    public long getSize() { return content.length; }
    public byte[] getBytes() { return content; }
    public InputStream getInputStream() { return new ByteArrayInputStream(content); }
    public void transferTo(File dest) throws IOException, IllegalStateException {
        Files.write(dest.toPath(), content);
    }
}
