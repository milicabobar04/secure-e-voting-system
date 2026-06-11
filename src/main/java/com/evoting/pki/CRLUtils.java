package com.evoting.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class CRLUtils {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * Generise CRL listu za dato CA tijelo
     */
    public static X509CRL generateCRL(X509Certificate issuerCert, PrivateKey issuerPrivateKey, List<RevokedCertificateEntry> revokedCertificates, int validityDays) throws Exception{
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());

        Date thisUpdate = new Date();
        // Nakon ovog datuma CRL se smatra zastarjelim
        Date nextUpdate = new Date(thisUpdate.getTime() + (long) validityDays * 24 * 60 * 60 * 1000);

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        for(RevokedCertificateEntry entry: revokedCertificates){
            crlBuilder.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(), entry.getReason());
        }
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(issuerCert.getPublicKey().getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerPrivateKey);
        X509CRLHolder crlHolder = crlBuilder.build(signer);

        return new JcaX509CRLConverter()
                .setProvider("BC")
                .getCRL(crlHolder);
    }
    /**
     * Sačuva CRL u fajl
     */
    public static void saveCRL(X509CRL crl, String filePath) throws Exception {
        // Sačuva CRL u binarni (.crl) fajl koristeći DER kodiranje
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(crl.getEncoded());
        }
    }
    /**
     * Učitava CRL iz fajla
     */
    public static X509CRL loadCRL(String filePath) throws Exception{
        try(FileInputStream fis = new FileInputStream(filePath)){
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            return (X509CRL) cf.generateCRL(fis);
        }
    }
    /**
     * Provjera da li sertifikat opozvan
     */
    public static boolean isCertificateRevoked(X509Certificate cert, X509CRL crl){
        if(crl == null){
            return false;
        }
        X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
        return entry != null;
    }
    /**
     * Dobija informacije o svim opozvanim sertifikatima iz CRL-a
     */
    public static Set<? extends X509CRLEntry> getRevokedCertificates(X509CRL crl) {
        return crl.getRevokedCertificates();
    }
    /**
     * Provjerava validnost CRL-a
     */
    public static boolean isValidCRL(X509CRL crl, X509Certificate issuerCert){
        try{
            // Provjera potpisa
            crl.verify(issuerCert.getPublicKey(), "BC");

            Date now = new Date();
            if(crl.getNextUpdate() != null && now.after(crl.getNextUpdate())){
                return false;
            }
            return true;
        }catch (Exception e){
            return false;
        }
    }

    /**
     * Pomoćna klasa za čuvanje informacija o opozvanom sertifikatu
     */
    public static class RevokedCertificateEntry{
        private BigInteger serialNumber;
        private Date revocationDate;
        private int reason;

        public RevokedCertificateEntry(BigInteger serialNumber, Date revocationDate, int reason) {
            this.serialNumber = serialNumber;
            this.revocationDate = revocationDate;
            this.reason = reason;
        }
        public RevokedCertificateEntry(BigInteger serialNumber, Date revocationDate) {
            this(serialNumber, revocationDate, CRLReason.unspecified);
        }

        public BigInteger getSerialNumber() {
            return serialNumber;
        }

        public Date getRevocationDate() {
            return revocationDate;
        }

        public int getReason() {
            return reason;
        }
        /**
         * Konstantne vrednosti za razloge opoziva (prema RFC 5280)
         */
        public static class RevocationReason {
            public static final int UNSPECIFIED = CRLReason.unspecified;
            public static final int KEY_COMPROMISE = CRLReason.keyCompromise;
            public static final int CA_COMPROMISE = CRLReason.cACompromise;
            public static final int AFFILIATION_CHANGED = CRLReason.affiliationChanged;
            public static final int SUPERSEDED = CRLReason.superseded;
            public static final int CESSATION_OF_OPERATION = CRLReason.cessationOfOperation;
            public static final int CERTIFICATE_HOLD = CRLReason.certificateHold;
            public static final int PRIVILEGE_WITHDRAWN = CRLReason.privilegeWithdrawn;
        }
    }
}
