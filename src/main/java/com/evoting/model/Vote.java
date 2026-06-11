package com.evoting.model;

import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Date;
import java.util.UUID;

public class Vote implements Serializable {
    private static final long serialVersionUID = 1L;
    private String voteId;
    private String electionId;
    private String voterId;
    private byte[] encryptedVote;
    private byte[] encryptedSymmetricKey;
    private byte[] digitalSignature;
    private byte[] metadataHmacOrganizer; // sacuvani sifrom organizatora
    private byte[] metadataHmacVoter; // sacuvani korisnika korisnika

    private Date timestamp;
    private boolean isVerified;
    private byte[] voteContentHash;

    public Vote(String electionId, String voterId) {
        this.voteId = UUID.randomUUID().toString();
        this.electionId = electionId;
        this.voterId = voterId;
        this.timestamp = new Date();
        this.isVerified = false;
    }
    public byte[] getVoteContentHash() { return voteContentHash; }
    public void setVoteContentHash(byte[] voteContentHash) { this.voteContentHash = voteContentHash; }

    public String getVoteId() {
        return voteId;
    }

    public String getElectionId() {
        return electionId;
    }

    public String getVoterId() {
        return voterId;
    }

    public byte[] getEncryptedVote() {
        return encryptedVote;
    }

    public void setEncryptedVote(byte[] encryptedVote) {
        this.encryptedVote = encryptedVote;
    }

    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public void setEncryptedSymmetricKey(byte[] encryptedSymmetricKey) {
        this.encryptedSymmetricKey = encryptedSymmetricKey;
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(byte[] digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public byte[] getMetadataHmacOrganizer() {
        return metadataHmacOrganizer;
    }

    public void setMetadataHmacOrganizer(byte[] metadataHmac) {
        this.metadataHmacOrganizer = metadataHmac;
    }
    public byte[] getMetadataHmacVoter() {
        return metadataHmacVoter;
    }

    public void setMetadataHmacVoter(byte[] metadataHmac) {
        this.metadataHmacVoter = metadataHmac;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public boolean isVerified() {
        return isVerified;
    }

    public void setVerified(boolean verified) {
        isVerified = verified;
    }

    /**
     * Generiše string metapodataka za HMAC
     */
    public String getMetadataString() {
        return voteId + "|" + electionId + "|" + voterId + "|" + timestamp.getTime();
    }
    /**
     *  Generiše string kompletnog sadržaja glasa koji će biti potpisan
     * */
    public String getCompleteVoteContent(String selectedCandidate) {
        return voteId + "|" +
                electionId + "|" +
                voterId + "|" +
                selectedCandidate + "|" +
                timestamp.getTime();
    }
    /**
     * Izračunava SHA-256 hash kompletnog sadržaja glasa
     */
    public static byte[] calculateVoteHash(String voteContent) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(voteContent.getBytes("UTF-8"));
    }
}
