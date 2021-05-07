package com.openbankproject.oauth2.model;

import java.util.stream.Stream;

public class ConsentsInfo {
    private ConsentInfo[] consents;

    public ConsentInfo[] getConsents() {
        return consents;
    }
    public ConsentInfo[] getConsents(String standard, String status) {
        return Stream.of(consents)
                .filter(i -> i.getApi_standard() != null)
                .filter(i -> i.getApi_standard().equalsIgnoreCase(standard))
                .filter(i -> !i.getStatus().equalsIgnoreCase(status))
                .toArray(ConsentInfo[]::new);
    }

    public void setConsents(ConsentInfo[] consents) {
        this.consents = consents;
    }
}

class ConsentInfo {
    private String consent_id;
    private String consumer_id;
    private String created_by_user_id;
    private String last_action_date;
    private String last_usage_date;
    private String status;
    private String api_standard;
    private String api_version;

    public String getConsent_id() {
        return consent_id;
    }

    public void setConsent_id(String consent_id) {
        this.consent_id = consent_id;
    }

    public String getConsumer_id() {
        return consumer_id;
    }

    public void setConsumer_id(String consumer_id) {
        this.consumer_id = consumer_id;
    }

    public String getCreated_by_user_id() {
        return created_by_user_id;
    }

    public void setCreated_by_user_id(String created_by_user_id) {
        this.created_by_user_id = created_by_user_id;
    }

    public String getLast_action_date() {
        return last_action_date;
    }

    public void setLast_action_date(String last_action_date) {
        this.last_action_date = last_action_date;
    }

    public String getLast_usage_date() {
        return last_usage_date;
    }

    public void setLast_usage_date(String last_usage_date) {
        this.last_usage_date = last_usage_date;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getApi_standard() {
        return api_standard;
    }

    public void setApi_standard(String api_standard) {
        this.api_standard = api_standard;
    }

    public String getApi_version() {
        return api_version;
    }

    public void setApi_version(String api_version) {
        this.api_version = api_version;
    }
}
