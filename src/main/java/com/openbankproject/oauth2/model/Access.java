package com.openbankproject.oauth2.model;

import java.util.List;

public class Access {
    private List<Account> accounts;
    private List<Balance> balances;

    public List<Account> getAccounts() {
        return accounts;
    }

    public void setAccounts(List<Account> accounts) {
        this.accounts = accounts;
    }

    public List<Balance> getBalances() {
        return balances;
    }

    public void setBalances(List<Balance> balances) {
        this.balances = balances;
    }
}
