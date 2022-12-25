package com.nortal.ocsp.mock;

import com.nortal.ocsp.mock.service.OcspResponderService;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@SpringBootTest
class ApplicationTests {

    @Autowired
    private OcspResponderService ocspResponderService;

    @Autowired
    private X509Certificate ocspRequesterCertificate;

    @Autowired
    private X509Certificate ocspResponderCertificate;

    @Test
    void ocsp() throws CertificateException, OCSPException, OperatorCreationException, IOException {
        JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
        DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
        CertificateID certId = new CertificateID(digestCalculator, new JcaX509CertificateHolder(ocspRequesterCertificate), ocspRequesterCertificate.getSerialNumber());
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        BigInteger nonce = BigInteger.valueOf(Instant.now().toEpochMilli());
        DEROctetString nonceDer = new DEROctetString(nonce.toByteArray());
        Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonceDer);
        Extensions exts = new Extensions(ext);
        ocspReqBuilder.addRequest(certId);
        ocspReqBuilder.setRequestExtensions(exts);
        OCSPReq ocspReq = ocspReqBuilder.build();

        byte[] ocspResponseData = ocspResponderService.response(ocspReq.getEncoded());

        OCSPResp ocspResp = new OCSPResp(ocspResponseData);
        BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
        assertThat(basicResp.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspResponderCertificate)), is(true));
    }
}
