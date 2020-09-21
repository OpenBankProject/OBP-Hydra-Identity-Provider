package com.openbankproject.oauth2.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class BankList {
    private List<Bank> banks;
}

@Data
class Bank {

    private String id;
    @JsonProperty("short_name")
    private String short_name;
    @JsonProperty("full_name")
    private String full_name;
}
