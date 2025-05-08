package org.example.testdigitalsignature.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

@Component
public class KeyStoreLoader {
    @Value("${keystore.path}")
    private String keystorePath;

    @Value("${keystore.password}")
    private String password;

    @Value("${keystore.alias}")
    private String alias;

    public PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new FileInputStream(keystorePath)) {
            ks.load(is, password.toCharArray());
        }
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    public Certificate getCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new FileInputStream(keystorePath)) {
            ks.load(is, password.toCharArray());
        }
        return ks.getCertificate(alias);
    }

    public PublicKey getPublicKey() throws Exception {
        return getCertificate().getPublicKey();
    }
}
