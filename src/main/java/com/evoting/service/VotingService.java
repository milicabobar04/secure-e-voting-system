package com.evoting.service;

import com.evoting.model.*;
import com.evoting.pki.CertificateUtils;
import com.evoting.storage.DataStore;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Servis za glasanje i brojanje glasova
 */
public class VotingService {
    private DataStore dataStore;
    private ElectionService electionManager;
    private static final String REPORTS_DIR = "reports";

    public VotingService(ElectionService electionManager) {
        this.dataStore = DataStore.getInstance();
        this.electionManager = electionManager;
    }

    /**
     * Glasač glasa za kandidata
     */
    public VoteResult castVote(Voter voter, String electionId, String selectedCandidate, String password) {
        try {
            // Provjera da li glasanje postoji
            Election election = dataStore.getElection(electionId);
            if (election == null) {
                return new VoteResult(false, "Glasanje ne postoji!", null);
            }

            // Provjera da li je glasanje aktivno
            if (!electionManager.isElectionActive(electionId)) {
                return new VoteResult(false, "Glasanje nije aktivno!", null);
            }

            // Provjera da li je kandidat validan
            if (!election.getCandidates().contains(selectedCandidate)) {
                return new VoteResult(false, "Nevalidan kandidat!", null);
            }

            // Provjera da li je glasač već glasao
            if (dataStore.hasVoterVoted(voter.getUniqueIdentifier(), electionId)) {
                return new VoteResult(false, "Već ste glasali za ovo glasanje!", null);
            }

            // Kreiranje glasa
            Vote vote = new Vote(electionId, voter.getUniqueIdentifier());

            // 1. KREIRANJE KOMPLETNOG SADRŽAJA GLASA
            String completeVoteContent = vote.getCompleteVoteContent(selectedCandidate);

            // 2. HASHOVANJE SADRŽAJA
            byte[] voteHash = Vote.calculateVoteHash(completeVoteContent);
            vote.setVoteContentHash(voteHash);

            // 3. DIGITALNI POTPIS
            PrivateKey voterPrivateKey = CertificateUtils.loadPrivateKey(voter.getPrivateKeyPath(), password);
            byte[] signature = VotingCryptoUtils.signVote(voteHash, voterPrivateKey);
            vote.setDigitalSignature(signature);

            // 4. ENKRIPCIJA GLASA SIMETRIČNIM KLJUČEM (AES)
            SecretKey aesKey = VotingCryptoUtils.generateAESKey();
            byte[] encryptedVote = VotingCryptoUtils.encryptVote(selectedCandidate, aesKey);
            vote.setEncryptedVote(encryptedVote);

            // 5. ENKRIPCIJA SIMETRIČNOG KLJUČA JAVNIM KLJUČEM ORGANIZATORA
            Organizer organizer = (Organizer) dataStore.getUserByIdentifier(election.getOrganizerId());
            byte[] encryptedKey = VotingCryptoUtils.encryptSymmetricKey(aesKey, CertificateUtils.loadCertificate(organizer.getCertificatePath()));
            vote.setEncryptedSymmetricKey(encryptedKey);

            // 6. HMAC ZA METAPODATKE
            String metadata = vote.getMetadataString();

            // A) HMAC ZA KORISNIKA (Ključ: Lozinka korisnika)
            byte[] hmacUser = VotingCryptoUtils.generateHMAC(metadata, password);
            vote.setMetadataHmacVoter(hmacUser);

            // B) HMAC ZA ORGANIZATORA (Ključ: AES ključ glasa)
            // Koristimo onaj isti aesKeyString koji je gore generisan
            String aesKeyString = Base64.getEncoder().encodeToString(aesKey.getEncoded());
            byte[] hmacOrg = VotingCryptoUtils.generateHMAC(metadata, aesKeyString);
            vote.setMetadataHmacOrganizer(hmacOrg);

            // Čuvanje glasa
            dataStore.saveVote(vote);

            return new VoteResult(true, "Glas uspješno upisan!", vote);

        } catch (Exception e) {
            e.printStackTrace();
            return new VoteResult(false, "Greška pri glasanju: " + e.getMessage(), null);
        }
    }

    /**
     * Verifikacija da je glas ispravno zabilježen
     */
    public VerificationResult verifyVote(Voter voter, String electionId, String password) {
        try {
            // Provjera da li je glasač glasao
            if (!dataStore.hasVoterVoted(voter.getUniqueIdentifier(), electionId)) {
                return new VerificationResult(false, "Niste glasali za ovo glasanje!");
            }

            // Dohvatanje glasa
            Vote vote = dataStore.getVoterVote(voter.getUniqueIdentifier(), electionId);

            // INTEGRITET METAPODATAKA
            boolean isHmacValid = VotingCryptoUtils.verifyHMAC(
                    vote.getMetadataString(),
                    vote.getMetadataHmacVoter(),
                    password
            );

            if (!isHmacValid) {
                return new VerificationResult(false, "Integritet metapodataka je narušen!");
            }

            // VERIFIKACIJA DIGITALNOG POTPISA
            X509Certificate voterCert = CertificateUtils.loadCertificate(voter.getCertificatePath());
            boolean signatureValid = VotingCryptoUtils.verifySignature(
                    vote.getVoteContentHash(),
                    vote.getDigitalSignature(),
                    voterCert
            );

            if (!signatureValid) {
                return new VerificationResult(false, "Digitalni potpis nije validan! Unijeli ste pogrešnog kandidata ili je glas izmenjen.");
            }

            vote.setVerified(true);

            return new VerificationResult(true,
                    "✓ Vaš glas je ISPRAVAN!\n");

        } catch (Exception e) {
            e.printStackTrace();
            return new VerificationResult(false, "Greška pri verifikaciji: " + e.getMessage());
        }
    }
    /**
     * Brojanje glasova (samo organizator)
     */
    public CountingResult countVotes(Organizer organizer, String electionId, String password) {
        try {
            // Provjera da li glasanje postoji
            Election election = dataStore.getElection(electionId);
            if (election == null) {
                return new CountingResult(false, "Glasanje ne postoji!", null, null);
            }

            // Provjera da li organizator može pristupiti
            if (!electionManager.canOrganizerAccessElection(organizer.getUniqueIdentifier(), electionId)) {
                return new CountingResult(false, "Nemate pristup ovom glasanju!", null, null);
            }

            // Provjera da li je glasanje završeno
            if (!electionManager.isElectionEnded(electionId)) {
                return new CountingResult(false, "Glasanje još nije završeno!", null, null);
            }

            // Dohvatanje svih glasova
            List<Vote> votes = dataStore.getVotesByElection(electionId);

            if (votes.isEmpty()) {
                return new CountingResult(false, "Nema glasova za brojanje!", null, null);
            }

            // Učitavanje privatnog ključa organizatora
            PrivateKey organizerPrivateKey = CertificateUtils.loadPrivateKey(
                    organizer.getPrivateKeyPath(),
                    password
            );

            // Brojanje glasova
            Map<String, Integer> results = new HashMap<>();
            for (String candidate : election.getCandidates()) {
                results.put(candidate, 0);
            }

            int validVotes = 0;
            int invalidVotes = 0;

            for (Vote vote : votes) {
                try {
                    // 1. DEKRIPTOVANJE SIMETRIČNOG KLJUČA
                    SecretKey aesKey = VotingCryptoUtils.decryptSymmetricKey(
                            vote.getEncryptedSymmetricKey(),
                            organizerPrivateKey
                    );
                    // Vraćamo ključ u String format za provjeru HMAC-a
                    String aesKeyString = Base64.getEncoder().encodeToString(aesKey.getEncoded());

                    // 2. PROVJERA HMAC-a ORGANIZATORA
                    boolean isHmacValid = VotingCryptoUtils.verifyHMAC(
                            vote.getMetadataString(),
                            vote.getMetadataHmacOrganizer(),
                            aesKeyString
                    );

                    if (!isHmacValid) {
                        System.err.println("Integritet metapodataka narušen za glas ID: " + vote.getVoteId());
                        invalidVotes++;
                        continue;
                    }

                    // 3. DEKRIPTOVANJE GLASA
                    String decryptedVote = VotingCryptoUtils.decryptVote(
                            vote.getEncryptedVote(),
                            aesKey
                    );

                    // Dodavanje glasa u rezultate
                    if (results.containsKey(decryptedVote)) {
                        results.put(decryptedVote, results.get(decryptedVote) + 1);
                        validVotes++;
                    } else {
                        invalidVotes++;
                    }

                } catch (Exception e) {
                    invalidVotes++;
                    System.err.println("Greška pri dekriptovanju glasa: " + e.getMessage());
                }
            }

            // Generisanje izvještaja
            String report = generateReport(election, results, validVotes, invalidVotes);

            // Digitalni potpis izvještaja
            byte[] signedReport = VotingCryptoUtils.signReport(report, organizerPrivateKey);

            // Čuvanje potpisanog izvještaja
            electionManager.setSignedReport(electionId, signedReport);

            // Označavanje glasanja kao prebrojano
            electionManager.markElectionAsCounted(electionId);

            String savedFilePath = saveReportToFile(electionId, report, signedReport);
            String message = "Glasovi prebrojani! Izvještaj sačuvan u: " + savedFilePath;

            return new CountingResult(true, message, results, report);

        } catch (Exception e) {
            e.printStackTrace();
            return new CountingResult(false, "Greška pri brojanju: " + e.getMessage(), null, null);
        }
    }
    /**
     * Pomoćna metoda za čuvanje izvještaja u fajl
     */
    private String saveReportToFile(String electionId, String reportContent, byte[] signature) throws IOException {
        String fileName = "election_" + electionId + "_report.txt";
        File file = new File(REPORTS_DIR, fileName);

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(reportContent);
            writer.write("\n\n");
            writer.write("============================================================\n");
            writer.write("CRYPTOGRAPHIC SIGNATURE (Base64):\n");
            writer.write("============================================================\n");
            writer.write(Base64.getEncoder().encodeToString(signature));
            writer.write("\n============================================================");
        }

        return file.getPath();
    }

    /**
     * Generisanje izvještaja o rezultatima
     */
    private String generateReport(Election election, Map<String, Integer> results, int validVotes, int invalidVotes) {
        StringBuilder report = new StringBuilder();
        report.append("=".repeat(60)).append("\n");
        report.append("IZVJEŠTAJ O REZULTATIMA GLASANJA\n");
        report.append("=".repeat(60)).append("\n\n");

        report.append("Naslov: ").append(election.getTitle()).append("\n");
        report.append("Opis: ").append(election.getDescription()).append("\n");
        report.append("Period glasanja: ").append(election.getStartDate()).append(" - ").append(election.getEndDate()).append("\n\n");

        report.append("REZULTATI:\n");
        report.append("-".repeat(60)).append("\n");

        // Sortiranje rezultata po broju glasova (opadajuće)
        List<Map.Entry<String, Integer>> sortedResults = new ArrayList<>(results.entrySet());
        sortedResults.sort((e1, e2) -> e2.getValue().compareTo(e1.getValue()));

        for (Map.Entry<String, Integer> entry : sortedResults) {
            String candidate = entry.getKey();
            int votes = entry.getValue();
            double percentage = validVotes > 0 ? (votes * 100.0 / validVotes) : 0;

            report.append(String.format("%-30s: %5d glasova (%.2f%%)\n", candidate, votes, percentage));
        }

        report.append("-".repeat(60)).append("\n");
        report.append(String.format("Ukupno validnih glasova: %d\n", validVotes));
        report.append(String.format("Ukupno nevalidnih glasova: %d\n", invalidVotes));
        report.append(String.format("UKUPNO: %d\n", validVotes + invalidVotes));

        report.append("\n").append("=".repeat(60)).append("\n");
        report.append("Datum generisanja: ").append(new Date()).append("\n");
        report.append("Digitalno potpisano\n");
        report.append("=".repeat(60)).append("\n");

        return report.toString();
    }

    /**
     * Provjerava da li je glasač glasao
     */
    public boolean hasVoterVoted(String voterId, String electionId) {
        return dataStore.hasVoterVoted(voterId, electionId);
    }

    // ==================== RESULT CLASSES ====================

    public static class VoteResult {
        private boolean success;
        private String message;
        private Vote vote;

        public VoteResult(boolean success, String message, Vote vote) {
            this.success = success;
            this.message = message;
            this.vote = vote;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public Vote getVote() { return vote; }
    }

    public static class VerificationResult {
        private boolean success;
        private String message;

        public VerificationResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }

    public static class CountingResult {
        private boolean success;
        private String message;
        private Map<String, Integer> results;
        private String report;

        public CountingResult(boolean success, String message, Map<String, Integer> results, String report) {
            this.success = success;
            this.message = message;
            this.results = results;
            this.report = report;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public Map<String, Integer> getResults() { return results; }
        public String getReport() { return report; }
    }
}