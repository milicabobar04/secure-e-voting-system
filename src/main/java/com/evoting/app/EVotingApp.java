package com.evoting.app;

import com.evoting.model.Election;
import com.evoting.model.Organizer;
import com.evoting.model.User;
import com.evoting.model.Voter;
import com.evoting.pki.PKIManager;
import com.evoting.service.AuthenticationService;
import com.evoting.service.ElectionService;
import com.evoting.service.VotingService;
import com.evoting.storage.DataStore;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class EVotingApp {
    private PKIManager pkiManager;
    private AuthenticationService authService;
    private ElectionService electionService;
    private VotingService votingService;
    private DataStore dataStore;
    private Scanner scanner;
    private User currentUser;
    private SimpleDateFormat dateFormat;

    public EVotingApp(){
        this.scanner=new Scanner(System.in);
        this.dataStore=DataStore.getInstance();
        this.dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm");
        this.currentUser=null;
    }
    /**
     * Inicjalizaija PKI sistema
     */
    public void initializePKI(){
        try{
            pkiManager =new PKIManager();
            pkiManager.initializePKI();

            authService = new AuthenticationService(pkiManager);
            electionService = new ElectionService();
            votingService = new VotingService(electionService);

        }catch (Exception e){
            System.err.println("Greska pri inicijalizaciji PKI sistema.");
            e.printStackTrace();
        }
    }

    /**
     * Ulazna tacka aplikacije
     */
    public static void main(String[] args){
        EVotingApp app = new EVotingApp();
        app.run();
    }
    /**
     * Pokretanje aplikacije
     */
    public void run(){
        printWelcome();
        initializePKI();

        while (true){
            if(currentUser == null){
                showMainMenu();
            }else{
                if(currentUser instanceof Organizer){
                    showOrganizerMenu();
                }else if(currentUser instanceof Voter){
                    showVoterMenu();
                }
            }
        }
    }
    private void printWelcome() {
        System.out.println("E-VOTING SISTEM");
    }

    // ==================== GLAVNI MENI ====================
    private void showMainMenu(){
        System.out.println("\n" + "=".repeat(60));
        System.out.println("GLAVNI MENI");
        System.out.println("=".repeat(60));
        System.out.println("1. Registracija");
        System.out.println("2. Prijava");
        System.out.println("0. Izlaz");
        System.out.println("=".repeat(60));

        int choice = readInt("Izaberite opciju: ");

        switch (choice) {
            case 1: showRegistrationMenu(); break;
            case 2: login(); break;
            case 0: exit(); break;
            default: System.out.println("Nepoznata opcija!");
        }
    }
    private void showRegistrationMenu(){
        System.out.println("\n=== REGISTRACIJA ===");
        System.out.println("1. Registracija kao Organizator");
        System.out.println("2. Registracija kao Glasač");
        System.out.println("0. Nazad");

        int choice = readInt("Izaberite opciju: ");

        switch (choice) {
            case 1: registerOrganizer(); break;
            case 2: registerVoter(); break;
            case 0: break;
            default: System.out.println("Nepoznata opcija!");
        }
    }
    // ==================== REGISTRACIJA ====================
    private void registerOrganizer(){
        System.out.println("\n=== REGISTRACIJA ORGANIZATORA ===");

        String orgName = readString("Naziv organizacije: ");
        String orgId = readString("Identifikacioni broj: ");
        String password = readPassword("Lozinka: ");
        String confirmPassword = readPassword("Potvrdite lozinku: ");

        if(!password.equals(confirmPassword)){
            System.out.println(" Lozinke se ne poklapaju!");
            return;
        }
        AuthenticationService.RegistrationResult result = authService.registerOrganizer(orgName, orgId, password);

        if(result.isSuccess()){
            System.out.println(result.getMessage());
            System.out.println("Sertifikat sačuvan: " + result.getCertificatePath());
            System.out.println("\nMOŽETE SE SADA PRIJAVITI!");
        }else {
            System.out.println(result.getMessage());
        }
    }
    private void registerVoter(){
        System.out.println("\n=== REGISTRACIJA GLASAČA ===");

        String firstName = readString("Ime: ");
        String lastName = readString("Prezime: ");
        String username = readString("Korisničko ime: ");
        String password = readPassword("Lozinka: ");
        String confirmPassword = readPassword("Potvrdite lozinku: ");

        if (!password.equals(confirmPassword)) {
            System.out.println("Lozinke se ne poklapaju!");
            return;
        }

        AuthenticationService.RegistrationResult result =
                authService.registerVoter(firstName, lastName, username, password);

        if (result.isSuccess()) {
            System.out.println(result.getMessage());
            System.out.println(" Sertifikat sačuvan: " + result.getCertificatePath());
            System.out.println("\nMOŽETE SE SADA PRIJAVITI!");
        } else {
            System.out.println(result.getMessage());
        }
    }
    // ==================== PRIJAVA ====================
    private void login() {
        System.out.println("\n=== PRIJAVA (KORAK 1/2) ===");
        System.out.println("Validacija sertifikata");

        String certPath = readString("Putanja do sertifikata: ");
        String password = readPassword("Lozinka za privatni ključ: ");

        AuthenticationService.ValidationResult validationResult = authService.validateCertificate(certPath, password);

        if (!validationResult.isSuccess()) {
            System.out.println(validationResult.getMessage());
            return;
        }

        System.out.println(validationResult.getMessage());

        User user = validationResult.getUser();

        if (!user.canLogin()) {
            System.out.println("Ne mоžete pristupiti nalogu!");
            return;
        }
        System.out.println("\n=== PRIJAVA (KORAK 2/2) ===");
        System.out.println("Unos identifikatora i lozinke");

        String identifier = readString("Identifikator (" +
                (user instanceof Organizer ? "organizacioni ID" : "korisničko ime") + "): ");
        String loginPassword = readPassword("Lozinka: ");

        AuthenticationService.LoginResult loginResult = authService.login(user, identifier, loginPassword);

        if (loginResult.isSuccess()) {
            currentUser = loginResult.getUser();
            System.out.println(loginResult.getMessage());
            System.out.println("Prijavljeni kao: " + currentUser.getUniqueIdentifier() +
                    " (" + currentUser.getUserType() + ")");
        } else {
            System.out.println(loginResult.getMessage());
            if (user.getFailedLoginAttempts() > 0) {
                System.out.println("Broj neuspješnih pokušaja: " +
                        user.getFailedLoginAttempts() + "/3");
            }
        }
    }
        // ==================== ORGANIZATOR MENI ====================
        private void showOrganizerMenu() {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("ORGANIZATOR: " + currentUser.getUniqueIdentifier());
            System.out.println("=".repeat(60));
            System.out.println("1. Kreiraj novo glasanje");
            System.out.println("2. Pregled mojih glasanja");
            System.out.println("3. Prebroj glasove");
            System.out.println("0. Odjava");
            System.out.println("=".repeat(60));

            int choice = readInt("Izaberite opciju: ");

            switch (choice) {
                case 1: createElection(); break;
                case 2: viewOrganizerElections(); break;
                case 3: countVotes(); break;
                case 0: logout(); break;
                default: System.out.println("✗ Nepoznata opcija!");
            }
        }
        private void createElection() {
            System.out.println("\n=== KREIRANJE GLASANJA ===");

            String title = readString("Naslov glasanja: ");
            String description = readString("Opis: ");

            Date startDate = readDate("Datum početka (dd.MM.yyyy HH:mm): ");
            Date endDate = readDate("Datum kraja (dd.MM.yyyy HH:mm): ");

            int numCandidates = readInt("Broj kandidata (2-5): ");

            if (numCandidates < 2 || numCandidates > 5) {
                System.out.println("Broj kandidata mora biti između 2 i 5!");
                return;
            }
            List<String> candidates = new ArrayList<>();
            for(int i=1; i<= numCandidates; i++){
                String candidate = readString("Kandidat " + i + ": ");
                if(candidates.contains(candidate)){
                    System.out.println("GREŠKA: Kandidat sa imenom '" + candidate + "' je već unesen!");
                    System.out.println("Molimo unesite drugo ime.");
                    i--;
                    continue;
                }
                candidates.add(candidate);
            }
            ElectionService.ElectionResult result = electionService.createElection(
                    (Organizer) currentUser, title, description, startDate, endDate,candidates
            );

            if (result.isSuccess()) {
                System.out.println(result.getMessage());
                System.out.println("ID glasanja: " + result.getElection().getElectionId());
            } else {
                System.out.println(result.getMessage());
            }
        }

        private void viewOrganizerElections(){
            System.out.println("\n=== MOJA GLASANJA ===");
            List<Election> elections = electionService.getOrganizerElections(
                    currentUser.getUniqueIdentifier()
            );
            if(elections.isEmpty()){
                System.out.println("Nemate kreiranih glasanja.");
                return;
            }
            for (Election election : elections) {
                printElectionInfo(election);
            }
        }

        private void countVotes(){
            System.out.println("\n=== BROJANJE GLASOVA ===");

            String electionId = readString("ID glasanja: ");
            String password = readPassword("Vaša lozinka: ");

            VotingService.CountingResult result = votingService.countVotes(
                    (Organizer) currentUser, electionId, password
            );

            if (result.isSuccess()) {
                System.out.println(result.getMessage());
                System.out.println("\n" + result.getReport());
            } else {
                System.out.println(result.getMessage());
            }
        }
        // ==================== GLASAČ MENI ====================
        private void showVoterMenu() {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("GLASAČ: " + ((Voter) currentUser).getFullName());
            System.out.println("=".repeat(60));
            System.out.println("1. Pregled aktivnih glasanja");
            System.out.println("2. Glasaj");
            System.out.println("3. Verifikuj glas");
            System.out.println("0. Odjava");
            System.out.println("=".repeat(60));

            int choice = readInt("Izaberite opciju: ");

            switch (choice) {
                case 1: viewActiveElections(); break;
                case 2: castVote(); break;
                case 3: verifyVote(); break;
                case 0: logout(); break;
                default: System.out.println("✗ Nepoznata opcija!");
            }
        }
        private void viewActiveElections(){
            System.out.println("\n=== AKTIVNA GLASANJA ===");
            List<Election> elections = electionService.getActiveElections();

            if(elections.isEmpty()){
                System.out.println("Trenutno nema aktivnih glasanja.");
                return;
            }
            for (Election election : elections) {
                printElectionInfo(election);

                boolean hasVoted = votingService.hasVoterVoted(
                        currentUser.getUniqueIdentifier(), election.getElectionId()
                );

                if (hasVoted) {
                    System.out.println("  ✓ Već ste glasali");
                }
                System.out.println();
            }
        }
        private void castVote(){
            System.out.println("\n=== GLASANJE ===");

            String electionId = readString("ID glasanja: ");
            Election election = electionService.getElection(electionId);
            if (election == null) {
                System.out.println("Glasanje ne postoji!");
                return;
            }
            if(!electionService.isElectionActive(electionId)){
                System.out.println("Glasanje nije aktivno! ");
                return;
            }
            if (votingService.hasVoterVoted(currentUser.getUniqueIdentifier(), electionId)) {
                System.out.println("Već ste glasali za ovo glasanje!");
                return;
            }
            System.out.println("\nGlasanje: " + election.getTitle());
            System.out.println("Kandidati:");
            List<String> candidates = election.getCandidates();
            for (int i = 0; i < candidates.size(); i++) {
                System.out.println("  " + (i + 1) + ". " + candidates.get(i));
            }
            int choice = readInt("\nIzaberite kandidata (1-" + candidates.size() + "): ");

            if(choice < 1 || choice > candidates.size()){
                System.out.println("Nevalidan izbor!");
                return;
            }
            String selectedCandidate = candidates.get(choice -1);

            System.out.println("\nIzabrali ste: " + selectedCandidate);
            String confirm = readString("Potvrdite (da/ne): ");

            if (!confirm.equalsIgnoreCase("da")) {
                System.out.println("Glasanje otkazano.");
                return;
            }
            String password = readPassword("Vaša lozinka: ");
            VotingService.VoteResult result = votingService.castVote(
                    (Voter) currentUser, electionId, selectedCandidate, password
            );
            if (result.isSuccess()) {
                System.out.println(result.getMessage());
                System.out.println("Vaš glas je enkriptovan i digitalno potpisan");
                System.out.println("ID glasa: " + result.getVote().getVoteId());
            } else {
                System.out.println(result.getMessage());
            }

        }
    private void verifyVote() {
        System.out.println("\n=== VERIFIKACIJA GLASA ===");

        String electionId = readString("ID glasanja: ");
        String password = readPassword("Vaša lozinka: ");

        VotingService.VerificationResult result = votingService.verifyVote(
                (Voter) currentUser, electionId, password
        );

        if (result.isSuccess()) {
            System.out.println(result.getMessage());
        } else {
            System.out.println(result.getMessage());
        }
    }
    // ==================== HELPER METODE ====================
    private void printElectionInfo(Election election) {
        System.out.println("\n" + "-".repeat(60));
        System.out.println("ID: " + election.getElectionId());
        System.out.println("Naslov: " + election.getTitle());
        System.out.println("Opis: " + election.getDescription());
        System.out.println("Period: " + dateFormat.format(election.getStartDate()) +
                " - " + dateFormat.format(election.getEndDate()));
        System.out.println("Status: " + election.getStatus());
        System.out.println("Broj glasova: " + electionService.getVoteCount(election.getElectionId()));
        System.out.println("Kandidati: " + String.join(", ", election.getCandidates()));
        System.out.println("-".repeat(60));
    }
    private void showStatistics() {
        dataStore.printStatistics();
    }

    private void logout() {
        System.out.println("\n✓ Uspješno ste se odjavili!");
        currentUser = null;
    }
    private void exit() {
        scanner.close();
        System.exit(0);
    }
    // ==================== INPUT HELPER METODE ====================
    private String readString(String prompt){
        System.out.print(prompt);
        return scanner.nextLine().trim();
    }
    private int readInt(String prompt) {
        while (true) {
            try {
                System.out.print(prompt);
                int value = Integer.parseInt(scanner.nextLine().trim());
                return value;
            } catch (NumberFormatException e) {
                System.out.println("Unesite validan broj!");
            }
        }
    }
    private String readPassword(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().trim();
    }
    private Date readDate(String prompt) {
        while (true) {
            try {
                System.out.print(prompt);
                String dateStr = scanner.nextLine().trim();
                return dateFormat.parse(dateStr);
            } catch (ParseException e) {
                System.out.println("Neispravan format! Koristite: dd.MM.yyyy HH:mm");
            }
        }
    }
}

