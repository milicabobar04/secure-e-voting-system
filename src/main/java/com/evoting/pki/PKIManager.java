package com.evoting.pki;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class PKIManager {
    private static final String PKI_DIR = "pki";
    private static final String ROOT_CA_DIR = PKI_DIR + "/root";
    private static final String ORGANIZER_CA_DIR = PKI_DIR + "/organizer";
    private static final String VOTER_CA_DIR = PKI_DIR + "/voter";
    private static final String CRL_DIR = PKI_DIR + "/crl";

    private CACertificate rootCA;
    private CACertificate organizerCA;
    private CACertificate voterCA;
    private Map<String, List<CRLUtils.RevokedCertificateEntry>> revokedCertificates;
    public PKIManager() {
        this.revokedCertificates = new HashMap<>();
        revokedCertificates.put("organizer", new ArrayList<>());
        revokedCertificates.put("voter", new ArrayList<>());
    }

    /**
     * Kreira potrebne direktorijume za PKI
     */
    private void createDirectories(){
        new File(ROOT_CA_DIR).mkdirs();
        new File(ORGANIZER_CA_DIR).mkdirs();
        new File(VOTER_CA_DIR).mkdirs();
        new File(PKI_DIR + "/certificates").mkdirs();
        new File(PKI_DIR + "/crl").mkdirs();
    }
    /**
     * Inicijalizuje PKI sistem
     * Kreira Root CA i dva subordinate CA (Organizer i Voter)
     */
    public void initializePKI() throws Exception {
        if (pkiExists()) {
            loadPKI();
        } else {
            createDirectories();
            rootCA = createRootCA();
            organizerCA = createOrganizerCA(rootCA);
            voterCA = createVoterCA(rootCA);
            createInitialCRLs();
        }
    }
    /**
     * Provjerava da li postoje ključni fajlovi (Root CA).
     */
    private boolean pkiExists() {
        File rootCert = new File(ROOT_CA_DIR + "/root-ca.crt");
        File rootKey = new File(ROOT_CA_DIR + "/root-ca.key");
        return rootCert.exists() && rootKey.exists();
    }
    /**
     * Učitava sertifikate, ključeve I postojeće opozvane sertifikate u memoriju.
     */
    private void loadPKI() throws Exception {
        // 1. Učitaj Root CA
        X509Certificate rootCert = CertificateUtils.loadCertificate(ROOT_CA_DIR + "/root-ca.crt");
        PrivateKey rootKey = loadPrivateKey(ROOT_CA_DIR + "/root-ca.key");
        this.rootCA = new CACertificate(rootCert, rootKey, "Root CA");

        // 2. Učitaj Organizer CA
        X509Certificate orgCert = CertificateUtils.loadCertificate(ORGANIZER_CA_DIR + "/organizer-ca.crt");
        PrivateKey orgKey = loadPrivateKey(ORGANIZER_CA_DIR + "/organizer-ca.key");
        this.organizerCA = new CACertificate(orgCert, orgKey, "Organizer CA");

        // 3. Učitaj Voter CA
        X509Certificate voterCert = CertificateUtils.loadCertificate(VOTER_CA_DIR + "/voter-ca.crt");
        PrivateKey voterKey = loadPrivateKey(VOTER_CA_DIR + "/voter-ca.key");
        this.voterCA = new CACertificate(voterCert, voterKey, "Voter CA");

        // 4. Učitaj CRL liste nazad u memoriju (Popunjavanje revokedCertificates mape)
        this.revokedCertificates.get("organizer").addAll(loadRevokedList(CRL_DIR + "/organizer-ca.crl"));
        this.revokedCertificates.get("voter").addAll(loadRevokedList(CRL_DIR + "/voter-ca.crl"));
    }
    private List<CRLUtils.RevokedCertificateEntry> loadRevokedList(String crlPath) {
        List<CRLUtils.RevokedCertificateEntry> list = new ArrayList<>();
        File file = new File(crlPath);

        if (!file.exists()) return list;

        try {
            X509CRL crl = CRLUtils.loadCRL(crlPath);
            Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();

            if (entries != null) {
                for (X509CRLEntry entry : entries) {
                    BigInteger serialNumber = entry.getSerialNumber();
                    Date revocationDate = entry.getRevocationDate();
                    int reasonCode = 0; // Default: Unspecified

                    // Pokušaj parsiranja razloga (Reason Code extension OID: 2.5.29.21)
                    byte[] extBytes = entry.getExtensionValue(Extension.reasonCode.getId());
                    if (extBytes != null) {
                        try {
                            // Dekodiranje ASN.1 strukture da dobijemo int vrijednost
                            ASN1OctetString octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(extBytes);
                            byte[] octets = octetString.getOctets();
                            ASN1Primitive primitive = ASN1Primitive.fromByteArray(octets);
                            if (primitive instanceof ASN1Enumerated) {
                                reasonCode = ((ASN1Enumerated) primitive).getValue().intValue();
                            }
                        } catch (Exception e) {
                            System.err.println("Greška pri parsiranju CRL reason koda: " + e.getMessage());
                        }
                    }

                    list.add(new CRLUtils.RevokedCertificateEntry(serialNumber, revocationDate, reasonCode));
                }
            }
        } catch (Exception e) {
            System.err.println("Greška pri učitavanju CRL liste (" + crlPath + "): " + e.getMessage());
        }
        return list;
    }
    // =============== Helper metode za cuvanje kljuceva CA tijela==================
    private void savePrivateKey(PrivateKey key, String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(key.getEncoded());
        }
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePrivate(spec);
    }
    /**
     * Kreira Root CA
     */
    public CACertificate createRootCA() throws Exception{
        KeyPair keyPair = CertificateUtils.generateKey();

        X509Certificate cert = CertificateUtils.createRootCACertificate(keyPair, "E-Voting Root CA",10 );
        CertificateUtils.saveCertificate(cert, ROOT_CA_DIR + "/root-ca.crt");
        savePrivateKey(keyPair.getPrivate(), ROOT_CA_DIR + "/root-ca.key");

        return new CACertificate(cert, keyPair.getPrivate(), "Root CA");
    }
    /**
     * Kreira Organizer CA (subordinate CA)
     */
    private CACertificate createOrganizerCA(CACertificate rootCA) throws Exception{
        KeyPair keyPair = CertificateUtils.generateKey();

        X509Certificate cert = CertificateUtils.createSubordinateCACertificate(keyPair, rootCA.getCertificate(), rootCA.getPrivateKey(), "E-Voting Organizer CA", "Organizer Certificate Authority", 5);
        CertificateUtils.saveCertificate(cert, ORGANIZER_CA_DIR + "/organizer-ca.crt" );
        savePrivateKey(keyPair.getPrivate(), ORGANIZER_CA_DIR + "/organizer-ca.key");

        return new CACertificate(cert, keyPair.getPrivate(), "Organizer CA");
    }
    /**
     * Kreira Voter CA (subordinate CA)
     */
    private CACertificate createVoterCA(CACertificate rootCA) throws Exception{
        KeyPair keyPair = CertificateUtils.generateKey();

        X509Certificate cert = CertificateUtils.createSubordinateCACertificate(keyPair, rootCA.getCertificate(), rootCA.getPrivateKey(),
                "E-Voting Voter CA",
                 "Voter Certificate Authority", 5);
        CertificateUtils.saveCertificate(cert,  VOTER_CA_DIR + "/voter-ca.crt");
        savePrivateKey(keyPair.getPrivate(), VOTER_CA_DIR + "/voter-ca.key");

        return new CACertificate(cert, keyPair.getPrivate(), "Voter CA");
    }
    /**
     * Izdaje sertifikat za organizatora
     */
    public X509Certificate issueOrganizerCertificate(String orgName, String orgID, KeyPair keyPair) throws Exception{
        if(organizerCA == null){
            throw new IllegalStateException("PKI sistem nije inicijalizovan!");
        }
        X500Name subject = CertificateUtils.createOrganizerName(orgName, orgID);

        return CertificateUtils.createEndEntityCertificate(keyPair, organizerCA.getCertificate(), organizerCA.getPrivateKey(), subject, true, 2);
    }
    /**
     * Izdaje sertifikat za glasača
     */
    public X509Certificate issueVoterCertificate(String firstName, String lastName, String username, KeyPair keyPair) throws Exception{
        if (voterCA == null){
            throw new IllegalStateException("PKI sistem nije inicijalizovan!");
        }
        X500Name subject = CertificateUtils.createVoterName(firstName, lastName, username);
        return CertificateUtils.createEndEntityCertificate(keyPair, voterCA.getCertificate(), voterCA.getPrivateKey(), subject, false, 2);
    }
    /**
     * Kreira inicijalne (prazne) CRL liste za oba CA
     */
    private void createInitialCRLs() throws Exception{
        X509CRL organizerCRL = CRLUtils.generateCRL(
                organizerCA.getCertificate(),
                organizerCA.getPrivateKey(),
                new ArrayList<>(),
                30
        );
        CRLUtils.saveCRL(organizerCRL, CRL_DIR + "/organizer-ca.crl");

        X509CRL voterCRL = CRLUtils.generateCRL(
                voterCA.getCertificate(),
                voterCA.getPrivateKey(),
                new ArrayList<>(),
                30
        );
        CRLUtils.saveCRL(voterCRL, CRL_DIR + "/voter-ca.crl");
    }
    /**
     * Opoziva sertifikat organizatora
     */
    public void revokeOrganizerCertificate(X509Certificate cert, int reason) throws Exception{
        revokeCertificate(cert, reason, "organizer", organizerCA, CRL_DIR + "/organizer-ca.crl");
    }
    /**
     * Opoziva sertifikat glasača
     */
    public void revokeVoterCertificate(X509Certificate cert, int reason) throws Exception {
        revokeCertificate(cert, reason, "voter", voterCA, CRL_DIR + "/voter-ca.crl");
    }
    private void revokeCertificate(X509Certificate cert, int reason, String caType, CACertificate ca, String crlPath) throws Exception{
        CRLUtils.RevokedCertificateEntry entry = new CRLUtils.RevokedCertificateEntry(
                cert.getSerialNumber(),
                new Date(),
                reason
        );
        revokedCertificates.get(caType).add(entry);

        X509CRL newCRL = CRLUtils.generateCRL(
                ca.getCertificate(),
                ca.getPrivateKey(),
                revokedCertificates.get(caType),
                30
        );
        CRLUtils.saveCRL(newCRL, crlPath);
    }
    /**
     * Provjera da li je sertifikat organizatora opozvan
     */
    public boolean isOrganizerCertificateRevoked(X509Certificate cert) throws Exception{
        X509CRL crl = CRLUtils.loadCRL(CRL_DIR + "/organizer-ca.crl");
        return CRLUtils.isCertificateRevoked(cert, crl);
    }
    /**
     * Provjerava da li je sertifikat glasača opozvan
     */
    public boolean isVoterCertificateRevoked(X509Certificate cert) throws Exception {
        X509CRL crl = CRLUtils.loadCRL(CRL_DIR + "/voter-ca.crl");
        return CRLUtils.isCertificateRevoked(cert, crl);
    }
    /**
     * Validira sertifikat (provjerava lanac i CRL)
     */
    public boolean validateCertificate(X509Certificate cert, boolean isOrganizer, String identifier, PrivateKey privateKey) throws Exception {
        // Proveri da li je sertifikat istekao
        try {
            cert.checkValidity();
        } catch (Exception e) {
            return false; // Sertifikat je istekao
        }

        // Provjeri potpis (lanac povjerenja)
        CACertificate issuerCA = isOrganizer ? organizerCA : voterCA;
        try {
            cert.verify(issuerCA.getCertificate().getPublicKey(), "BC");
        } catch (Exception e) {
            return false;
        }

        // Provjeri da li je opozvan
        boolean isRevoked = isOrganizer ?
                isOrganizerCertificateRevoked(cert) :
                isVoterCertificateRevoked(cert);

        if (isRevoked) {
            System.err.println("Validacija neuspješna: Sertifikat je opozvan");
            return false;
        }

        if (!verifyCertificateOwnership(cert, privateKey)) {
            System.err.println("Validacija neuspješna: Privatni ključ ne pripada sertifikatu");
            return false;
        }

        if (identifier != null && !identifier.isEmpty()) {
            if (!verifyIdentifier(cert, identifier, isOrganizer)) {
                System.err.println("Validacija neuspješna: Identifikator se ne poklapa");
                return false;
            }
        }

        return true;

    }

    /**
     * Ažurira CRL liste (poziva se periodično)
     */
    public void updateCRLs() throws Exception {
        X509CRL organizerCRL = CRLUtils.generateCRL(
                organizerCA.getCertificate(),
                organizerCA.getPrivateKey(),
                revokedCertificates.get("organizer"),
                30
        );
        CRLUtils.saveCRL(organizerCRL, CRL_DIR + "/organizer-ca.crl");

        X509CRL voterCRL = CRLUtils.generateCRL(
                voterCA.getCertificate(),
                voterCA.getPrivateKey(),
                revokedCertificates.get("voter"),
                30
        );
        CRLUtils.saveCRL(voterCRL, CRL_DIR + "/voter-ca.crl");

    }
    /**
     * Provjera da li sertifikat pripada korisniku na osnovu privatnog ključa
     */
    public static boolean verifyCertificateOwnership(X509Certificate cer, PrivateKey userPrivateKey){
        try{
            byte[] testData = "Ownership verification".getBytes();

            Signature signature = Signature.getInstance("SHA256withRSA", "BC");
            signature.initSign(userPrivateKey);
            signature.update(testData);
            byte[] signedData = signature.sign();

            signature.initVerify(cer.getPublicKey());
            signature.update(testData);

            return signature.verify(signedData);
        }catch (Exception e){
            return false;
        }
    }
    /**
     * Provjera identifikatora iz sertifikata
     * Za organizatore provjerava SERIALNUMBER (organization ID)
     * Za glasače provjerava CN ili UID (username)
     */
    private boolean verifyIdentifier(X509Certificate cert, String identifier, boolean isOrganizer) {
        try {
            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());

            if (isOrganizer) {
                // ORGANIZER → provjera SERIALNUMBER (organization ID)
                RDN[] serialNumbers = x500Name.getRDNs(BCStyle.SERIALNUMBER);
                if (serialNumbers != null && serialNumbers.length > 0) {
                    String orgId = serialNumbers[0].getFirst().getValue().toString();
                    return orgId.equals(identifier);
                }
                return false;

            } else {
                // VOTER → prvo provjera UID (username)
                RDN[] uids = x500Name.getRDNs(BCStyle.UID);
                if (uids != null && uids.length > 0) {
                    String uid = uids[0].getFirst().getValue().toString();
                    return uid.equals(identifier);
                }

                // Ako nema UID, fallback na CN
                RDN[] cns = x500Name.getRDNs(BCStyle.CN);
                if (cns != null && cns.length > 0) {
                    String cn = cns[0].getFirst().getValue().toString();
                    return cn.toLowerCase().contains(identifier.toLowerCase());
                }

                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }


}
