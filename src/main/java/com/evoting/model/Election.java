package com.evoting.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class Election implements Serializable {
    private static final long serialVersionUID = 1L;
    private String electionId;
    private String title;
    private String description;
    private Date startDate;
    private Date endDate;
    private String organizerId;
    private List<String> candidates;
    private ElectionStatus status;
    private byte[] signedReport;

    public Election(String title, String description, Date startDate, Date endDate,
                    String organizerId, List<String> candidates) {
        this.electionId = UUID.randomUUID().toString();
        this.title = title;
        this.description = description;
        this.startDate = startDate;
        this.endDate = endDate;
        this.organizerId = organizerId;
        this.candidates = new ArrayList<>(candidates);
        this.status = ElectionStatus.PENDING;
    }

    public String getElectionId() {
        return electionId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }

    public String getOrganizerId() {
        return organizerId;
    }

    public List<String> getCandidates() {
        return new ArrayList<>(candidates);
    }

    public void setCandidates(List<String> candidates) {
        this.candidates = new ArrayList<>(candidates);
    }

    public ElectionStatus getStatus() {
        return status;
    }

    public void setStatus(ElectionStatus status) {
        this.status = status;
    }

    public byte[] getSignedReport() {
        return signedReport;
    }

    public void setSignedReport(byte[] signedReport) {
        this.signedReport = signedReport;
    }
    public boolean isActive(){
        Date now = new Date();
        return now.after(startDate) && now.before(endDate) && status == ElectionStatus.ACTIVE;
    }
    public boolean hasEnded(){
        Date now = new Date();
        return now.after(endDate);
    }
    public void updateStatus() {
        Date now = new Date();
        if (now.before(startDate)) {
            status = ElectionStatus.PENDING;
        } else if (now.after(startDate) && now.before(endDate)) {
            status = ElectionStatus.ACTIVE;
        } else if (now.after(endDate) && status != ElectionStatus.COUNTED) {
            status = ElectionStatus.ENDED;
        }
    }
    public enum ElectionStatus {
        PENDING,    // Čeka da počne
        ACTIVE,     // Trenutno aktivno
        ENDED,      // Završeno, ali nije prebrojano
        COUNTED     // Prebrojano
    }
}
