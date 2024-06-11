package com.openbankproject.oauth2.model;

import java.util.stream.Stream;

public class AccountMini {
    private String id;
    private String label;
    private AccountRouting[] account_routings;
    
    public boolean hasIban() {
        return Stream.of(account_routings).anyMatch(i -> i.getScheme().equalsIgnoreCase("IBAN"));
    }    
    public boolean hasIban(String iban) {
        return Stream.of(account_routings).anyMatch(i -> i.getAddress().equalsIgnoreCase(iban));
    }    
    public String getIban() {
        return Stream.of(account_routings).filter(i -> i.getScheme().equalsIgnoreCase("IBAN")).map(i -> i.getAddress()).findAny().orElse("");
    }

    public AccountRouting[] getAccount_routings() {
        return account_routings;
    }

    public void setAccount_routings(AccountRouting[] account_routings) {
        this.account_routings = account_routings;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }
}
