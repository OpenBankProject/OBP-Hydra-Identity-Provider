package com.openbankproject.oauth2.model;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class Accounts {
    private AccountMini[] accounts;

    public AccountMini[] getAccounts() {
        return accounts;
    }
    public AccountMini[] getIbanAccounts() {
        return Stream.of(accounts)
                .filter(accountMini -> accountMini.hasIban()).toArray(AccountMini[]::new);
    }
    public AccountMini[] getIbanAccounts(String[] ibans) {
        List<String> otherList = Arrays.asList(ibans);
        Stream<AccountMini> result = Stream.of(accounts).filter(x -> otherList.contains(x.getIban()));
        return result.toArray(AccountMini[]::new);
    }
    public AccountMini[] getAllAccounts() {
        Stream<AccountMini> result = Stream.of(accounts);
        return result.toArray(AccountMini[]::new);
    }

    public void setAccounts(AccountMini[] accounts) {
        this.accounts = accounts;
    }
    public String[] accountIds() {
        return Stream.of(accounts).map(AccountMini::getId).toArray(String[]::new);
    }
    public String[] accountIdsWithIban() {
        return Stream.of(accounts)
                .filter(accountMini -> accountMini.hasIban())
                .map(AccountMini::getId).toArray(String[]::new);
    }
    public String[] getIbans() {
        return Stream.of(accounts)
                .filter(accountMini -> accountMini.hasIban())
                .map(AccountMini::getIban).toArray(String[]::new);
    }
    public Map<String, String> getIdtoIbanMap() {
        Map<String, String> result = new HashMap<>();
        AccountMini[] accounts = Stream.of(this.accounts).toArray(AccountMini[]::new);
        for (AccountMini accountMini : accounts) {
            result.put(accountMini.getId(), accountMini.getIban());
        }
        return result;
    }
}

class AccountMini {
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

class AccountRouting {
    private String scheme;
    private String address;

    public String getScheme() {
        return scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}
