package com.evoting.model;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;

public class VotingCryptoUtils {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * Generisemo nacumican AES kljuc (256-bit)
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        return keyGen.generateKey();
    }
    /**
     * Enkripcija glasa pomocu AES algoritma
     */
    public static byte[] encryptVote(String voteDate, SecretKey aesKey) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Genrisemo IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE,aesKey,ivSpec);
        byte[] encryptedData = cipher.doFinal(voteDate.getBytes("UTF-8"));

        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return result;
    }
    /**
     * Dekripcija glasa pomocu AES kljuca
     */
    public static String decryptVote(byte[] encryptedData, SecretKey aesKey) throws Exception{
        byte[] iv = new byte[16];
        System.arraycopy(encryptedData, 0, iv, 0 ,16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] ciphertext = new byte[encryptedData.length - 16];
        System.arraycopy(encryptedData, 16, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decryptedData = cipher.doFinal(ciphertext);

        return new String(decryptedData, "UTF-8");
    }
    /**
     * Enkriptuj simetricni kljuc javnim RSA kljucem organizatora
     */
    public static byte[] encryptSymmetricKey(SecretKey aesKey, X509Certificate organizerCert) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, organizerCert.getPublicKey());
        return cipher.doFinal(aesKey.getEncoded());
    }
    /**
     * Dekripcija simtericnog kljuca privatnim RSA kljucem organizatora
     */
    public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey organizerPrivateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, organizerPrivateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, "AES");
    }
    /**
     * Kreiranje digitalnog potpisa glasa
     */
    public static byte[] signVote(byte[] voteHash, PrivateKey voterPrivateKey ) throws Exception{
        Signature signature = Signature.getInstance("RSA", "BC");

        signature.initSign(voterPrivateKey);
        signature.update(voteHash);

        return signature.sign();
    }
    /**
     * Verifikacija digitalnog potpisa glasaca
     */
    public static boolean verifySignature (byte[] voteContentHash, byte[] digitalSignature, X509Certificate voterCert) throws Exception{
        Signature publicSignature = Signature.getInstance("RSA", "BC");

        publicSignature.initVerify(voterCert.getPublicKey());
        publicSignature.update(voteContentHash);

        return publicSignature.verify(digitalSignature);
    }
    /**
     * Generiše HMAC-SHA256 kao niz bajtova.
     */
    public static byte[] generateHMAC(String metadata, String secretKeyString) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(
                secretKeyString.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        return mac.doFinal(metadata.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Verifikuje da li primljeni HMAC odgovara metapodacima.
     */
    public static boolean verifyHMAC(String metadata, byte[] hmac, String secretKeyString) throws Exception {
        byte[] calculatedHmac = generateHMAC(metadata, secretKeyString);

        return MessageDigest.isEqual(calculatedHmac, hmac);
    }
    /**
     * Hashujemo lozinku pomocu SHA-256
     */
    public static String hashPassword(String password) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); // klasa za hash fukncije
        byte[] hash = digest.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for(byte b: hash){
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
    /**
     * Kreiranje digitalnog potpisa izvjestaja o rezultatima glasanja
     */
    public static byte[] signReport(String reportData, PrivateKey organizerPrivateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(organizerPrivateKey);
        signature.update(reportData.getBytes("UTF-8"));
        return signature.sign();
    }
    /**
     * Verifikacija digitalnog potpisa izvjestaja
     */
    public static boolean verifyReportSignature(String reportData, byte[] digitalSigniture, X509Certificate organizerCert) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(organizerCert.getPublicKey());
        signature.update(reportData.getBytes("UTF-8"));
        return signature.verify(digitalSigniture);
    }
}
