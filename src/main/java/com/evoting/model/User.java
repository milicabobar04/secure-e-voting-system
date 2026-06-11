package com.evoting.model;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * Apstraktna bazna klasa za sve korisnike sistema
 * Sadrži zajedničke atribute i metode za Organizer i Voter
 */
public abstract class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String passwordHash;
    private transient X509Certificate certificate;
    private String certificatePath;
    private String privateKeyPath;
    private int failedLoginAttempts;
    private boolean isLocked;
    private boolean isRevoked;

    public User(String passwordHash) {
        this.passwordHash = passwordHash;
        this.failedLoginAttempts = 0;
        this.isLocked = false;
        this.isRevoked = false;
    }

    /**
     * Jedinstveni identifikator korisnika
     * Za organizatore: organizationId
     * Za glasače: username
     */
    public abstract String getUniqueIdentifier();

    /**
     * Tip korisnika (ORGANIZER ili VOTER)
     */
    public abstract String getUserType();

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }
    public String getCertificatePath() { return certificatePath; }
    public void setCertificatePath(String certificatePath) { this.certificatePath = certificatePath; }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public boolean isLocked() {
        return isLocked;
    }

    public void setLocked(boolean locked) {
        isLocked = locked;
    }

    public boolean isRevoked() {
        return isRevoked;
    }

    public void setRevoked(boolean revoked) {
        isRevoked = revoked;
    }

    /**
     * Inkrementira broj neuspješnih pokušaja prijave
     * Ako dosegne 3, zaključava nalog
     */
    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= 3) {
            this.isLocked = true;
        }
    }

    /**
     * Resetuje broj neuspješnih pokušaja nakon uspješne prijave
     */
    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
    }

    /**
     * Provjerava da li je nalog zaključan ili opozvan
     */
    public boolean canLogin() {
        return !isLocked && !isRevoked;
    }

    /**
     * Provjerava da li korisnik ima sertifikat
     */
    public boolean hasCertificate() {
        return certificate != null;
    }

    /**
     * Provjerava da li korisnik ima privatni ključ
     */
    public boolean hasPrivateKey() {
        return privateKeyPath != null && !privateKeyPath.isEmpty();
    }

    @Override
    public String toString() {
        return "User{" +
                "type=" + getUserType() +
                ", identifier='" + getUniqueIdentifier() + '\'' +
                ", hasCertificate=" + hasCertificate() +
                ", isLocked=" + isLocked +
                ", isRevoked=" + isRevoked +
                ", failedAttempts=" + failedLoginAttempts +
                '}';
    }
}