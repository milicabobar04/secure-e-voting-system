package com.evoting.pki;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CACertificate {
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private String caName;

    public CACertificate(X509Certificate certificate, PrivateKey privateKey, String caName) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.caName = caName;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getCaName() {
        return caName;
    }

}