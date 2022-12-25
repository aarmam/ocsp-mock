package com.nortal.ocsp.mock.service;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class OcspResponderService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final PublicKey ocspPublicKey;
    private final PrivateKey ocspPrivateKey;
    private final X509Certificate ocspCertificate;

    @SneakyThrows
    public byte[] response(byte[] ocspRequest) {
        OCSPReq ocspReq = new OCSPReq(ocspRequest);

        BasicOCSPRespBuilder basicOcspRespBuilder = getBasicOCSPRespBuilder();

        Extension ocspNonceExtension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ocspNonceExtension != null) {
            basicOcspRespBuilder.setResponseExtensions(new Extensions(new Extension[]{ocspNonceExtension}));
        }

        for (Req req : ocspReq.getRequestList()) {
            basicOcspRespBuilder.addResponse(req.getCertID(), CertificateStatus.GOOD);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(ocspPrivateKey);
        X509CertificateHolder[] chain = getCertChain();
        BasicOCSPResp basicOCSPResp = basicOcspRespBuilder.build(signer, chain, new Date());
        OCSPRespBuilder respGen = new OCSPRespBuilder();
        OCSPResp ocspResp = respGen.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);
        return ocspResp.getEncoded();
    }

    private BasicOCSPRespBuilder getBasicOCSPRespBuilder() throws IOException, NoSuchAlgorithmException {
        DLSequence seq = (DLSequence) ASN1Primitive.fromByteArray(ocspPublicKey.getEncoded());
        DERBitString item = (DERBitString) seq.getObjectAt(1);
        byte[] digest = MessageDigest.getInstance("SHA1").digest(item.getOctets());
        ResponderID responderID = new ResponderID(new DEROctetString(digest));
        return new BasicOCSPRespBuilder(new RespID(responderID));
    }

    private X509CertificateHolder[] getCertChain() throws IOException, CertificateEncodingException {
        X509CertificateHolder[] chain = new X509CertificateHolder[1];
        chain[0] = new X509CertificateHolder(ocspCertificate.getEncoded());
        return chain;
    }
}
