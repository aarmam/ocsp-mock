package com.nortal.ocsp.mock.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Configuration
public class OcspResponderConfiguration {

    @Bean
    public KeyStore ocspResponderKeyStore(OcspResponderProperties ocspProperties, ResourceLoader loader) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Resource resource = loader.getResource(ocspProperties.keyStorePath());
        KeyStore trustStore = KeyStore.getInstance(ocspProperties.keyStoreType());
        trustStore.load(resource.getInputStream(), ocspProperties.keyStorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    public X509Certificate ocspResponderCertificate(OcspResponderProperties ocspProperties, KeyStore ocspResponderKeyStore) throws KeyStoreException {
        return (X509Certificate) ocspResponderKeyStore.getCertificate(ocspProperties.keyAlias());
    }

    @Bean
    public PrivateKey ocspResponderPrivateKey(OcspResponderProperties ocspProperties, KeyStore ocspResponderKeyStore) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        return (PrivateKey) ocspResponderKeyStore.getKey(ocspProperties.keyAlias(), ocspProperties.keyPassword().toCharArray());
    }

    @Bean
    public PublicKey ocspPublicKey(X509Certificate ocspResponderCertificate) {
        return ocspResponderCertificate.getPublicKey();
    }

}
