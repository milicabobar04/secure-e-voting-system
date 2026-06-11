package com.evoting.service;

import com.evoting.model.Election;
import com.evoting.model.Organizer;
import com.evoting.storage.DataStore;

import java.util.Date;
import java.util.List;

public class ElectionService {
    private DataStore dataStore;

    public ElectionService(){
        this.dataStore = DataStore.getInstance();
    }
    /**
     * Kreiramo novo glasanje
     */
    public ElectionResult createElection(Organizer organizer, String title, String description, Date startDate, Date endDate, List<String> candidates){
        try{
            // Validacija kandidata (2 - 5)
            if(candidates == null || candidates.size() < 2 || candidates.size() > 5){
                return new ElectionResult(false, "Broj kandidata mora biti između 2 i 5!", null);
            }
            // Validacija datuma
            if (startDate.after(endDate)) {
                return new ElectionResult(false, "Datum početka mora biti prije datuma kraja!", null);
            }

            Date now = new Date();
            if (endDate.before(now)) {
                return new ElectionResult(false, "Datum kraja ne može biti u prošlosti!", null);
            }

            // Kreiranje glasanja
            Election election = new Election(
                    title,
                    description,
                    startDate,
                    endDate,
                    organizer.getUniqueIdentifier(),
                    candidates
            );
            election.updateStatus();
            dataStore.saveElection(election);
            return new ElectionResult(true, "Glasanje uspješno kreirano!", election);

        }catch (Exception e){
            e.printStackTrace();
            return new ElectionResult(false, "Greška pri kreiranju glasanja: " + e.getMessage(), null);
        }
    }

    /**
     * Dohvata sve aktivne izbore
     */
    public List<Election> getActiveElections() {
        List<Election> elections = dataStore.getAllElections();

        // Ažuriranje statusa
        for (Election election : elections) {
            election.updateStatus();
            dataStore.updateElection(election);
        }

        return dataStore.getActiveElections();
    }

    /**
     * Dohvata sva glasanja organizatora
     */
    public List<Election> getOrganizerElections(String organizerId) {
        List<Election> elections = dataStore.getElectionsByOrganizer(organizerId);

        // Ažuriranje statusa
        for (Election election : elections) {
            election.updateStatus();
            dataStore.updateElection(election);
        }

        return elections;
    }
    /**
     * Dohvata glasanje po ID-u
     */
    public Election getElection(String electionId) {
        Election election = dataStore.getElection(electionId);

        if (election != null) {
            election.updateStatus();
            dataStore.updateElection(election);
        }

        return election;
    }
    /**
     * Provjerava da li je glasanje aktivno
     */
    public boolean isElectionActive(String electionId) {
        Election election = dataStore.getElection(electionId);

        if (election == null) {
            return false;
        }

        election.updateStatus();
        return election.isActive();
    }
    /**
     * Provjerava da li je glasanje završeno
     */
    public boolean isElectionEnded(String electionId) {
        Election election = dataStore.getElection(electionId);

        if (election == null) {
            return false;
        }

        election.updateStatus();
        return election.hasEnded();
    }
    /**
     * Dohvata broj glasova za glasanje
     */
    public int getVoteCount(String electionId) {
        return dataStore.getVoteCount(electionId);
    }
    /**
     * Ažurira status glasanja
     */
    public void updateElectionStatus(String electionId) {
        Election election = dataStore.getElection(electionId);

        if (election != null) {
            election.updateStatus();
            dataStore.updateElection(election);
        }
    }
    /**
     * Označava glasanje kao prebrojano
     */
    public void markElectionAsCounted(String electionId) {
        Election election = dataStore.getElection(electionId);

        if (election != null) {
            election.setStatus(Election.ElectionStatus.COUNTED);
            dataStore.updateElection(election);
        }
    }
    /**
     * Postavlja digitalno potpisan izvještaj
     */
    public void setSignedReport(String electionId, byte[] signedReport) {
        Election election = dataStore.getElection(electionId);

        if (election != null) {
            election.setSignedReport(signedReport);
            dataStore.updateElection(election);
        }
    }
    /**
     * Dohvata digitalno potpisan izvještaj
     */
    public byte[] getSignedReport(String electionId) {
        Election election = dataStore.getElection(electionId);
        return election != null ? election.getSignedReport() : null;
    }
    /**
     * Provjerava da li organizator može da pristupa glasanju
     */
    public boolean canOrganizerAccessElection(String organizerId, String electionId) {
        Election election = dataStore.getElection(electionId);
        return election != null && election.getOrganizerId().equals(organizerId);
    }
    // ==================== RESULT CLASS ====================

    public static class ElectionResult {
        private boolean success;
        private String message;
        private Election election;

        public ElectionResult(boolean success, String message, Election election) {
            this.success = success;
            this.message = message;
            this.election = election;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public Election getElection() { return election; }
    }
}
