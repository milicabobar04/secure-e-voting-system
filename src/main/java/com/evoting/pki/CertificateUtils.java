package com.evoting.pki;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

public class CertificateUtils {
    static{
        // Dodajemo Bouncy Castle provajdere na sistem
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * Generiše par ključeva (RSA 2048-bit)
     */
    public static KeyPair generateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    /**
     * Kreira X500Name za CA
     */
    public static X500Name createCAName(String commonName, String organization){
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.CN, commonName); // CN (Common Name) -  glavno ime entiteta
        builder.addRDN(BCStyle.O, organization); // O (Organization) - naziv organizacije
        builder.addRDN(BCStyle.C, "BA"); // C (Country) - "BA" (Bosna i Hercegovina).

        return builder.build();
    }
    /**
     * Kreira X500Name za organizatora
     */
    public static X500Name createOrganizerName(String orgName, String orgID){
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, orgName); // CN (Common Name) na naziv organizacije
        builder.addRDN(BCStyle.O, orgName); // O (Organization) - takođe naziv organizacije
        builder.addRDN(BCStyle.OU, "Organizer"); // OU (Organizational Unit) na fiksnu vrijednost "Organizer"
        builder.addRDN(BCStyle.SERIALNUMBER, orgID); // SERIALNUMBER - identifikacioni broj organizacije
        builder.addRDN(BCStyle.C, "BA"); // C (Country) - "BA" (Bosna i Hercegovina)
        return builder.build();
    }
    /**
     * Kreira X500Name za glasača
     */
    public static X500Name createVoterName(String firstName, String lastName, String username){
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, firstName + " " + lastName); // CN (Common Name) se formira kao puno ime i prezime glasača
        // GIVENNAME i SURNAME razdvajaju ime i prezime u zasebna polja sertifikata
        builder.addRDN(BCStyle.GIVENNAME, firstName);
        builder.addRDN(BCStyle.SURNAME, lastName);
        builder.addRDN(BCStyle.UID, username); // UID (User ID) se koristi za čuvanje jedinstvenog korisničkog imena
        builder.addRDN(BCStyle.OU, "Voter"); // OU (Organizational Unit) definiše ulogu korisnika
        builder.addRDN(BCStyle.C, "BA"); // C (Country) postavlja oznaku države
        return builder.build();
    }
    /**
     * Kreira root CA sertifikat (self-signed)
     */
    public static X509Certificate createRootCACertificate(KeyPair keyPair, String commonName, int validityYears) throws Exception{
        X500Name issuer = createCAName(commonName, "E-Voting Root CA");
        X500Name subject = issuer; // samopotpisano

        // Jedinstveni serijski  broj od 128 bita
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        // Vremenski okvira važenja sertifikata
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (long) validityYears * 365 * 24 * 60 * 60 * 1000);

        // Inicijalizacija buildera koji spaja sve podatke i javni ključ u X.509 strukturu
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );
        // Oznaka da je ovo CA sertifikat.
        // 'true' u BasicConstraints dozvoljava ovom sertifikatu da potpisuje druge sertifikate.
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        // Potpisivanje sertifikata (keyCertSign) i potpisivanje CRL lista (cRLSign)
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // Jedinstveni identifikator ključa subjekta (pomaže u izgradnji lanca povjerenja)
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyPair.getPublic().getEncoded()));

        // Potipisaivanje koristenjem hash algoritma (SHA-256) i asimetricni algoritam (RSA) i privatni kljuc
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(keyPair.getPrivate());

        // Konvertuje ga u standardni Java X509Certificate objekat
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
    /**
     * Kreira podredjene CA sertifikat (potpisuje ga Root CA)
     */
    public static X509Certificate createSubordinateCACertificate(KeyPair subCAKeyPair, X509Certificate rootCACert, PrivateKey rootCAPrivateKey, String commonName, String organization, int validity) throws Exception{
        // Root CA potpisuje, kreiramo podredjenog CA
        X500Name issuer = new X500Name(rootCACert.getSubjectX500Principal().getName());
        X500Name subject = createCAName(commonName, organization);

        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (long) validity * 365 * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                subCAKeyPair.getPublic()
        );

        // BasicConstraints – označava da je ovo CA sertifikat
        // 0 znači da ne može potpisivati druge CA
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        certificateBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
        );
        // SubjectKeyIdentifier (SKI) – identifikator javnog ključa podređenog CA
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(subCAKeyPair.getPublic().getEncoded()));
        // AuthorityKeyIdentifier (AKI) – identifikator ključa koji potpisuje
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(rootCACert.getPublicKey().getEncoded()));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(rootCAPrivateKey);

        X509CertificateHolder certHolder = certificateBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
    /**
     * Kreira end-entity sertifikat (za organizatora ili glasača)
     */
    public static X509Certificate createEndEntityCertificate(KeyPair entityKeyPair, X509Certificate caCert, PrivateKey caPrivateKey, X500Name subject, boolean isOrganizer, int validityYears) throws Exception{
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());

        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (long) validityYears * 365 * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                entityKeyPair.getPublic()
        );

        // Nije CA i ne može izdavati druge sertifikate
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if(isOrganizer){
            // keyUsage – za šta sertifikat može da se koristi
            // digitalSignature – za digitalni potpis
            // keyEncipherment – za šifrovanje ključeva
            // dataEncipherment – za šifrovanje podataka
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));
            // extendedKeyUsage – dodatne svrhe sertifikata
            // emailProtection – zaštita emaila
            // codeSigning – potpisivanje koda
            certBuilder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(new KeyPurposeId[]{
                            KeyPurposeId.id_kp_emailProtection,
                            KeyPurposeId.id_kp_codeSigning
                    })
            );
        }else{
            // digitalSignature – glasač može digitalno potpisivati poruke (glasove)
            // nonRepudiation – glasač ne može poreći da je poslao poruku (potpis ne može biti osporen)
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
            // extendedKeyUsage za glasača je samo emailProtection
            // znači sertifikat može da se koristi za autentifikaciju/zaštitu email komunikacije
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));

        }
        // Hash vrijednost subject i authority key
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(entityKeyPair.getPublic().getEncoded()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(caCert.getPublicKey().getEncoded()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(caPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
    /**
     * Sačuva sertifikat u fajl
     */
    public static void saveCertificate(X509Certificate cert, String filePath) throws Exception{
        try(FileOutputStream fos = new FileOutputStream(filePath)){
            fos.write(cert.getEncoded());
        }
    }
    /**
     * Ucitavanje sertfikata iz fajla
     */
    public static X509Certificate loadCertificate(String certPath) throws Exception{
        FileInputStream fis = new FileInputStream(certPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }
    /**
     * Ekstrakcija identifikatora iz sertifikata
     */
    public static String extractIdentifier(X509Certificate cert) {
        X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());

        // SERIALNUMBER – za organizatore
        RDN[] serialNumbers = x500Name.getRDNs(BCStyle.SERIALNUMBER);
        if (serialNumbers != null && serialNumbers.length > 0) {
            return serialNumbers[0].getFirst().getValue().toString();
        }

        // UID – za glasače
        RDN[] uids = x500Name.getRDNs(BCStyle.UID);
        if (uids != null && uids.length > 0) {
            return uids[0].getFirst().getValue().toString();
        }

        return null;
    }

    /**
     * Sačuva privatni ključ u fajl (enkriptovan)
     */
    /*
        LOZINKA + SALT
                ↓ (PBKDF2)
          IZVEDENI KLJUČ (AES KEY)
                ↓
        PRIVATNI KLJUČ
                ↓ (XOR sa IV + AES enkripcija CBC)
        ENKRIPTOVANI KLJUČ
                ↓
        FAJL: [SALT][IV][ENKRIPTOVANI KLJUČ]
    */

    public static void savePrivateKey(PrivateKey key, String filePath, String password) throws Exception {
        // Generiše se salt za PBKDF2
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        // Izvedemo ključ iz lozinke pomoću PBKDF2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Generišemo IV (Initialization Vector)
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Enkriptuj privatni ključ
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedKey = cipher.doFinal(key.getEncoded());

        // Sačuvamo salt + IV + enkriptovani ključ
        try(FileOutputStream fos = new FileOutputStream(filePath)){
            fos.write(salt);
            fos.write(iv);
            fos.write(encryptedKey);
        }
    }
    /**
     * Čita enkriptovani ključ i dekriptuje ga pomoću lozinke
     */
    public static PrivateKey loadPrivateKey(String filePath, String password) throws Exception{
        // Ucitavamo fajl
        byte[] fileContent;
        try(FileInputStream fis = new FileInputStream(filePath)){
            fileContent = fis.readAllBytes();
        }
        // Ekstrakcija salt-a
        byte[] salt = new byte[16];
        System.arraycopy(fileContent, 0, salt, 0, 16);

        // Ekstrakcija IV
        byte[] iv = new byte[16];
        System.arraycopy(fileContent, 16, iv, 0, 16);

        // Ekstrakcija enkriptovanog kljuca
        byte[] encryptedKey = new byte[fileContent.length - 32];
        System.arraycopy(fileContent, 32, encryptedKey, 0, encryptedKey.length);

        // Izvedemo kljuc iz lozinke
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Dekriptujemo privatni kljuc
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);

        // Konvertujemo bajtove u PrivateKey
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
