package org.example.testdigitalsignature.common;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.PdfSigner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ExtendedPdfSigner extends PdfSigner {
    public ExtendedPdfSigner(PdfReader reader, OutputStream outputStream, StampingProperties properties) throws IOException {
        super(reader, outputStream, properties);
    }

    public InputStream getDocumentRangeStream() throws IOException {
        return getRangeStream();
    }

}
