package com.evoting.storage;

import com.evoting.model.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory skladište podataka za aplikaciju
 * Thread-safe implementacija koristeći ConcurrentHashMap
 * Podržava serijalizaciju i deserijalizaciju podataka
 */
public class DataStore {
    private static DataStore instance;
    private static final String DATA_FILE = "pki/data/datastore.dat";

    // Skladišta podataka
    private Map<String, User> users;                    // Key: uniqueIdentifier (orgId ili username)
    private Map<String, Election> elections;            // Key: electionId
    private Map<String, Vote> votes;                    // Key: voteId
    private Map<String, List<Vote>> votesByElection;   // Key: electionId, Value: lista glasova
    private Map<String, Vote> voterElectionVotes;      // Key: voterId+electionId, Value: glas (sprečava duplo glasanje)

    private DataStore() {
        this.users = new ConcurrentHashMap<>();
        this.elections = new ConcurrentHashMap<>();
        this.votes = new ConcurrentHashMap<>();
        this.votesByElection = new ConcurrentHashMap<>();
        this.voterElectionVotes = new ConcurrentHashMap<>();

        // Automatsko učitavanje podataka pri inicijalizaciji
        loadFromFile();

        // Registrovanje shutdown hook-a za automatsko čuvanje
        registerShutdownHook();
    }

    public static synchronized DataStore getInstance() {
        if (instance == null) {
            instance = new DataStore();
        }
        return instance;
    }

    /**
     * Registruje shutdown hook za automatsko čuvanje podataka pri gašenju aplikacije
     */
    private void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            saveToFile();
        }));
    }

    /**
     * Serijalizacija - čuvanje svih podataka u fajl
     */
    public synchronized void saveToFile() {
        File dataFile = new File(DATA_FILE);

        // Kreiranje direktorijuma ako ne postoji
        if (dataFile.getParentFile() != null) {
            dataFile.getParentFile().mkdirs();
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(dataFile))) {

            DataSnapshot snapshot = new DataSnapshot(
                    users,
                    elections,
                    votes,
                    votesByElection,
                    voterElectionVotes
            );

            oos.writeObject(snapshot);
            oos.flush();


        } catch (IOException e) {
            System.err.println("Greška pri čuvanju podataka: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Deserijalizacija - učitavanje podataka iz fajla
     */
    public synchronized void loadFromFile() {
        File dataFile = new File(DATA_FILE);

        if (dataFile.exists()) {
            if (loadFromFileHelper(dataFile)) {
                return;
            }
        }
    }

    /**
     * Helper metoda za učitavanje iz fajla
     */
    private boolean loadFromFileHelper(File file) {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(file))) {

            DataSnapshot snapshot = (DataSnapshot) ois.readObject();

            this.users = new ConcurrentHashMap<>(snapshot.users);
            this.elections = new ConcurrentHashMap<>(snapshot.elections);
            this.votes = new ConcurrentHashMap<>(snapshot.votes);
            this.votesByElection = new ConcurrentHashMap<>(snapshot.votesByElection);
            this.voterElectionVotes = new ConcurrentHashMap<>(snapshot.voterElectionVotes);

            return true;

        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Greška pri učitavanju iz " + file.getName() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Manuelno čuvanje podataka
     */
    public void save() {
        saveToFile();
    }

    /**
     * Manuelno učitavanje podataka
     */
    public void load() {
        loadFromFile();
    }

    // ==================== USER OPERATIONS ====================

    public void saveUser(User user) {
        users.put(user.getUniqueIdentifier(), user);
    }

    public User getUserByIdentifier(String identifier) {
        return users.get(identifier);
    }

    public boolean userExists(String identifier) {
        return users.containsKey(identifier);
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    public List<Organizer> getAllOrganizers() {
        return users.values().stream()
                .filter(u -> u instanceof Organizer)
                .map(u -> (Organizer) u)
                .collect(Collectors.toList());
    }

    public List<Voter> getAllVoters() {
        return users.values().stream()
                .filter(u -> u instanceof Voter)
                .map(u -> (Voter) u)
                .collect(Collectors.toList());
    }

    // ==================== ELECTION OPERATIONS ====================

    public void saveElection(Election election) {
        elections.put(election.getElectionId(), election);
        votesByElection.putIfAbsent(election.getElectionId(), new ArrayList<>());
    }

    public Election getElection(String electionId) {
        return elections.get(electionId);
    }

    public List<Election> getAllElections() {
        return new ArrayList<>(elections.values());
    }

    public List<Election> getElectionsByOrganizer(String organizerId) {
        return elections.values().stream()
                .filter(e -> e.getOrganizerId().equals(organizerId))
                .collect(Collectors.toList());
    }

    public List<Election> getActiveElections() {
        return elections.values().stream()
                .filter(e -> e.isActive())
                .collect(Collectors.toList());
    }

    public void updateElection(Election election) {
        elections.put(election.getElectionId(), election);
    }

    // ==================== VOTE OPERATIONS ====================

    public void saveVote(Vote vote) {
        votes.put(vote.getVoteId(), vote);

        // Dodajemo u listu glasova za glasanje
        votesByElection.computeIfAbsent(vote.getElectionId(), k -> new ArrayList<>()).add(vote);

        // Označimo da je glasač glasao za ovo glasanje
        String key = vote.getVoterId() + "_" + vote.getElectionId();
        voterElectionVotes.put(key, vote);
    }

    public Vote getVote(String voteId) {
        return votes.get(voteId);
    }

    public List<Vote> getVotesByElection(String electionId) {
        return votesByElection.getOrDefault(electionId, new ArrayList<>());
    }

    public boolean hasVoterVoted(String voterId, String electionId) {
        String key = voterId + "_" + electionId;
        return voterElectionVotes.containsKey(key);
    }

    public Vote getVoterVote(String voterId, String electionId) {
        String key = voterId + "_" + electionId;
        return voterElectionVotes.get(key);
    }

    public int getVoteCount(String electionId) {
        return votesByElection.getOrDefault(electionId, new ArrayList<>()).size();
    }

    public void clear() {
        users.clear();
        elections.clear();
        votes.clear();
        votesByElection.clear();
        voterElectionVotes.clear();
    }

    public void printStatistics() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("DATA STORE STATISTIKA");
        System.out.println("=".repeat(50));
        System.out.println("Ukupno korisnika: " + users.size());
        System.out.println("  - Organizatora: " + getAllOrganizers().size());
        System.out.println("  - Glasača: " + getAllVoters().size());
        System.out.println("Ukupno glasanja: " + elections.size());
        System.out.println("  - Aktivnih: " + getActiveElections().size());
        System.out.println("Ukupno glasova: " + votes.size());
        System.out.println("=".repeat(50));
    }

    // ==================== SNAPSHOT CLASS ====================

    /**
     * Pomoćna klasa za serijalizaciju svih podataka
     */
    private static class DataSnapshot implements Serializable {
        private static final long serialVersionUID = 1L;

        private final Map<String, User> users;
        private final Map<String, Election> elections;
        private final Map<String, Vote> votes;
        private final Map<String, List<Vote>> votesByElection;
        private final Map<String, Vote> voterElectionVotes;

        public DataSnapshot(
                Map<String, User> users,
                Map<String, Election> elections,
                Map<String, Vote> votes,
                Map<String, List<Vote>> votesByElection,
                Map<String, Vote> voterElectionVotes) {

            this.users = new HashMap<>(users);
            this.elections = new HashMap<>(elections);
            this.votes = new HashMap<>(votes);
            this.votesByElection = new HashMap<>(votesByElection);
            this.voterElectionVotes = new HashMap<>(voterElectionVotes);
        }
    }
}