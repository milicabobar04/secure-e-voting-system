package com.evoting.model;

import java.io.Serializable;

public class Voter extends User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String firstName;
    private String lastName;
    private String username;

    public Voter(String passwordHash, String firstName, String lastName, String username) {
        super(passwordHash);
        this.firstName = firstName;
        this.lastName = lastName;
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getUniqueIdentifier() {
        return username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    @Override
    public String getUserType() {
        return "VOTER";
    }
}