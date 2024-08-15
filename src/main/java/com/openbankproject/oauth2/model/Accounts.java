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

    public AccountMini[] filterByRouting(String scheme, String address) {
        Stream<AccountMini> result = Stream.of(accounts).filter(
                x -> Stream.of(x.getAccount_routings())
                        .anyMatch(
                                i -> i.getScheme().equalsIgnoreCase(scheme) && i.getAddress().equalsIgnoreCase(address)
                        )
        );
        return result.toArray(AccountMini[]::new);
    }
    public AccountMini[] filterByAccountId(String accountId) {
        Stream<AccountMini> result = Stream.of(accounts).filter(
                x -> Stream.of(x.getId()).anyMatch(id -> id.equalsIgnoreCase(accountId))
        );
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
