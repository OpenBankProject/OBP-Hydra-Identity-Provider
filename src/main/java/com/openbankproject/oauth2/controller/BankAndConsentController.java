package com.openbankproject.oauth2.controller;

import com.openbankproject.oauth2.model.BankList;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;

@Controller
public class BankAndConsentController {

    @Value("${oauth2.public_url}/oauth2/token")
    private String hydraTokenUrl;

    @Value("${obp.base_url}/obp/v4.0.0/users/current")
    private String currentUserUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks")
    private String getBanksUrl;

    @Resource()
    private RestTemplate resetTemplate;

    public String showBankConsentPage(@RequestParam("login_challenge") String login_challenge, Model model) {
        BankList bankList = resetTemplate.getForObject(getBanksUrl, BankList.class);
        model.addAttribute("bankList", bankList);
        model.addAttribute("login_challenge", login_challenge);
        return "";
    }
}
