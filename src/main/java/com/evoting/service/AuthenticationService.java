package com.evoting.service;

import com.evoting.model.Organizer;
import com.evoting.model.User;
import com.evoting.model.Voter;
import com.evoting.model.VotingCryptoUtils;
import com.evoting.pki.CRLUtils;
import com.evoting.pki.CertificateUtils;
import com.evoting.pki.PKIManager;
import com.evoting.storage.DataStore;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


 /** Servis za autentifikaciju korisnika
  * Upravlja registracijom, prijavom i validacijom sertifikata
  * */
public class AuthenticationService {
    private PKIManager pkiManager;
    private DataStore dataStore;
    private static final String CERTS_DIR = "pki/certificates";
    private static final String KEYS_DIR = "pki/keys";
    private static final int MAX_FAILED_ATTEMPTS = 3;

    public AuthenticationService(PKIManager pkiManager){
        this.pkiManager = pkiManager;
        this.dataStore = DataStore.getInstance();
        new File(KEYS_DIR).mkdirs();
    }
    /**
     * Registracija organizatora
     */
    public RegistrationResult registerOrganizer(String organizationName, String organizationId, String password) {
        try {
            // Provjera da li organizacija već postoji
            if (dataStore.userExists(organizationId)) {
                return new RegistrationResult(false, "Organizacija sa ovim ID-om već postoji!", null);
            }

            // Hashovanje lozinke
            String passwordHash = VotingCryptoUtils.hashPassword(password);

            // Kreiranje korisnika
            Organizer organizer = new Organizer(passwordHash, organizationName, organizationId);

            // Generisanje para ključeva
            KeyPair keyPair = CertificateUtils.generateKey();

            // Izdavanje sertifikata
            X509Certificate cert = pkiManager.issueOrganizerCertificate(
                    organizationName,
                    organizationId,
                    keyPair
            );

            // Postavljanje sertifikata
            organizer.setCertificate(cert);

            // Čuvanje privatnog ključa (enkriptovan lozinkom)
            String keyPath = KEYS_DIR + "/organizer_" + organizationId + ".key";
            CertificateUtils.savePrivateKey(keyPair.getPrivate(), keyPath, password);
            organizer.setPrivateKeyPath(keyPath);

            // Čuvanje sertifikata
            String certPath = CERTS_DIR + "/organizer_" + organizationId + ".crt";
            CertificateUtils.saveCertificate(cert, certPath);
            organizer.setCertificatePath(certPath);

            // Čuvanje korisnika u bazu
            dataStore.saveUser(organizer);

            return new RegistrationResult(true, "Organizator uspješno registrovan!", certPath);

        } catch (Exception e) {
            e.printStackTrace();
            return new RegistrationResult(false, "Greška pri registraciji: " + e.getMessage(), null);
        }
    }
    /**
     * Registracija glasača
     */
    public RegistrationResult registerVoter(String firstName, String lastName, String username, String password) {
        try {
            // Provjera da li korisničko ime već postoji
            if (dataStore.userExists(username)) {
                return new RegistrationResult(false, "Korisničko ime već postoji!", null);
            }

            // Hashovanje lozinke
            String passwordHash = VotingCryptoUtils.hashPassword(password);

            // Kreiranje korisnika
            Voter voter = new Voter(passwordHash, firstName, lastName, username);

            // Generisanje para ključeva
            KeyPair keyPair = CertificateUtils.generateKey();

            // Izdavanje sertifikata
            X509Certificate cert = pkiManager.issueVoterCertificate(
                    firstName,
                    lastName,
                    username,
                    keyPair
            );

            // Postavljanje sertifikata
            voter.setCertificate(cert);

            // Čuvanje privatnog ključa (enkriptovan lozinkom)
            String keyPath = KEYS_DIR + "/voter_" + username + ".key";
            CertificateUtils.savePrivateKey(keyPair.getPrivate(), keyPath, password);
            voter.setPrivateKeyPath(keyPath);

            // Čuvanje sertifikata
            String certPath = CERTS_DIR + "/voter_" + username + ".crt";
            CertificateUtils.saveCertificate(cert, certPath);
            voter.setCertificatePath(certPath);

            // Čuvanje korisnika u bazu
            dataStore.saveUser(voter);

            return new RegistrationResult(true, "Glasač uspješno registrovan!", certPath);

        } catch (Exception e) {
            e.printStackTrace();
            return new RegistrationResult(false, "Greška pri registraciji: " + e.getMessage(), null);
        }
    }

    /**
     * Validacija sertifikata (prvi korak)
     */
    public ValidationResult validateCertificate(String certPath, String password){
        try{
            // Ucitavanje sertifikata
            X509Certificate cert = CertificateUtils.loadCertificate(certPath);

            // Ekstrakcija id iz sertifikata
            String identifier = CertificateUtils.extractIdentifier(cert);

            // Provjera da li korisnik postoji
            User user = dataStore.getUserByIdentifier(identifier);
            if(user == null){
                return new ValidationResult(false, "Korisnik ne postoji u sistemu!", null);
            }

            //Ucitavanje privatnog kljuca
            PrivateKey privateKey;
            try{
                privateKey = CertificateUtils.loadPrivateKey(user.getPrivateKeyPath(), password);
            }catch (Exception e){
                handleFailedLogin(user);

                int remaining = MAX_FAILED_ATTEMPTS - user.getFailedLoginAttempts();
                String msg = (remaining > 0)
                        ? "Pogrešna lozinka za privatni ključ! Preostalo pokušaja: " + remaining
                        : "Pogrešna lozinka! Vaš sertifikat je opozvan.";

                return new ValidationResult(false, msg, null);
            }



            // Validacija sertifikata kroz PKI
            boolean isOrganizer = user instanceof Organizer;
            boolean isValid = pkiManager.validateCertificate(cert, isOrganizer, identifier, privateKey);

            if (!isValid) {
                return new ValidationResult(false, "Sertifikat nije validan!", null);
            }

            return new ValidationResult(true, "Sertifikat je validan!", user);
        }catch (Exception e){
            e.printStackTrace();
            return new ValidationResult(false, "Greška pri validaciji: " + e.getMessage(), null);
        }
    }
    /**
     * Prijava sa identifikatorom i lozinkom (drugi korak)
     */
    public LoginResult login(User user, String identifier, String password){
        try{
            if(!user.getUniqueIdentifier().equals(identifier)){
                handleFailedLogin(user);
                return new LoginResult(false, "Pogrešan identifikator!", null);
            }
            String passwordHash = VotingCryptoUtils.hashPassword(password);
            if (!user.getPasswordHash().equals(passwordHash)) {
                handleFailedLogin(user);
                return new LoginResult(false, "Pogrešna lozinka!", null);
            }
            user.resetFailedAttempts();
            dataStore.saveUser(user);
            return new LoginResult(true, "Uspješna prijava!", user);

        }catch(Exception e){
            e.printStackTrace();
            return new LoginResult(false, "Greška pri prijavi: " + e.getMessage(), null);
        }
    }
    /**
     * Obrada neuspješne prijave
     */
    private void handleFailedLogin(User user) {
        user.incrementFailedAttempts();
        if(user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS){
            // Opozivamo sertifikat
            try{
                boolean isOrganizer = user instanceof Organizer;
                if(isOrganizer){
                    pkiManager.revokeOrganizerCertificate(user.getCertificate(), CRLUtils.RevokedCertificateEntry.RevocationReason.KEY_COMPROMISE);
                }else{
                    pkiManager.revokeVoterCertificate(
                            CertificateUtils.loadCertificate(user.getCertificatePath()),
                            CRLUtils.RevokedCertificateEntry.RevocationReason.KEY_COMPROMISE
                    );
                }
                user.setRevoked(true);
                System.out.println("UPOZORENJE: Sertifikat korisnika " + user.getUniqueIdentifier() + " je opozvan nakon 3 neuspješna pokušaja!");
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        dataStore.saveUser(user);
    }

    /**
     * Ucitavanje sertifikata iz fajl
     */
    // ==================== RESULT CLASSES ====================
    public static class RegistrationResult{
        private boolean success;
        private String message;
        private String certificatePath;
        public RegistrationResult(boolean success, String message, String certificatePath) {
            this.success = success;
            this.message = message;
            this.certificatePath = certificatePath;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public String getCertificatePath() { return certificatePath; }
    }
    public static class LoginResult {
        private boolean success;
        private String message;
        private User user;

        public LoginResult(boolean success, String message, User user) {
            this.success = success;
            this.message = message;
            this.user = user;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
    }
    public static class ValidationResult {
        private boolean success;
        private String message;
        private User user;

        public ValidationResult(boolean success, String message, User user) {
            this.success = success;
            this.message = message;
            this.user = user;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
    }



}
