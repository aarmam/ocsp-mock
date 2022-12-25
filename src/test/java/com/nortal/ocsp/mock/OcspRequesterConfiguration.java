package com.nortal.ocsp.mock;

import com.nortal.ocsp.mock.configuration.OcspResponderProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@TestConfiguration
public class OcspRequesterConfiguration {

    @Bean
    public KeyStore ocspRequesterKeyStore(ResourceLoader loader) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Resource resource = loader.getResource("classpath:ocsp-requester.p12");
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(resource.getInputStream(), "changeit".toCharArray());
        return trustStore;
    }

    @Bean
    public X509Certificate ocspRequesterCertificate(OcspResponderProperties ocspProperties, KeyStore ocspKeyStore) throws KeyStoreException {
        return (X509Certificate) ocspKeyStore.getCertificate(ocspProperties.keyAlias());
    }

    @Bean
    public PrivateKey ocspRequesterPrivateKey(OcspResponderProperties ocspProperties, KeyStore ocspKeyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        return (PrivateKey) ocspKeyStore.getKey(ocspProperties.keyAlias(), ocspProperties.keyPassword().toCharArray());
    }

    @Bean
    public PublicKey ocspRequesterPublicKey(X509Certificate ocspCertificate) {
        return ocspCertificate.getPublicKey();
    }

}
