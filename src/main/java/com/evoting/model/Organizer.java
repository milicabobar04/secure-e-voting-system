package com.evoting.model;

import java.io.Serializable;

public class Organizer extends User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String organizationName;
    private String organizationId;

    public Organizer(String passwordHash, String organizationName, String organizationId) {
        super(passwordHash);
        this.organizationName = organizationName;
        this.organizationId = organizationId;
    }

    @Override
    public String getUniqueIdentifier() {
        return organizationId;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getOrganizationId() {
        return organizationId;
    }

    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    @Override
    public String getUserType() {
        return "ORGANIZER";
    }
}