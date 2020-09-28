package com.openbankproject.oauth2.controller;

import com.openbankproject.oauth2.model.Accounts;
import com.openbankproject.oauth2.model.DirectLoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.AcceptLoginRequest;
import sh.ory.hydra.model.CompletedRequest;
import sh.ory.hydra.model.LoginRequest;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static com.openbankproject.oauth2.util.ControllerUtils.*;

@Controller
public class LoginController {
    private static Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Value("${obp.base_url}")
    private String obpBaseUrl;

    @Value("${obp.base_url}/my/logins/direct")
    private String directLoginUrl;

    @Value("${obp.base_url}/mx-open-finance/v0.0.1/account-access-consents/CONSENT_ID")
    private String getConsentUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID")
    private String getBankUrl;

    @Value("${consumer_key}")
    private String consumerKey;

    @Resource
    private RestTemplate restTemplate;

    @Resource
    private AdminApi hydraAdmin;

    //show login page
    @GetMapping(value="/login", params = "login_challenge")
    public String loginFromHydra(@RequestParam String login_challenge,
                                 Model model, HttpSession session){
        model.addAttribute("obp_url", obpBaseUrl);
        model.addAttribute("login_challenge", login_challenge);

        try {
            LoginRequest loginRequest = hydraAdmin.getLoginRequest(login_challenge);
            String requestUrl = loginRequest.getRequestUrl();
            String consentId = getConsentId(requestUrl);
            String bankId = getBankId(requestUrl);
            if(bankId == null) {
                model.addAttribute("errorMsg", "Query parameter `bank_id` is mandatory! ");
                return "error";
            }
            if(consentId  == null) {
                model.addAttribute(
                        "errorMsg", "Query parameter `consent_id` is mandatory! " +
                        "Hint: create client_credentials accessToken, create Account Access Consents by call endpoint `CreateAccountAccessConsents` (/mx-open-finance/v0.0.1/account-access-consents), " +
                         "with header Authorization: Authorization: Bearer <accessToken>");
                return "error";
            }
            // TODO validate consentId is valid
            session.setAttribute("consent_id", consentId);
            // TODO validate bankId is valid
            session.setAttribute("bank_id", bankId);
            // login before and checked rememberMe.
            if(loginRequest.getSkip()) {
                AcceptLoginRequest acceptLoginRequest = new AcceptLoginRequest();
                acceptLoginRequest.setSubject(loginRequest.getSubject());
                CompletedRequest response = hydraAdmin.acceptLoginRequest(login_challenge, acceptLoginRequest);
                return "redirect:" + response.getRedirectTo();
            } else {
                return "login";
            }
        } catch (ApiException e) {
            model.addAttribute("errorMsg", "login_challenge parameter is not correct!");
           return "error";
        }
    }

    //do authentication
    @PostMapping(value="/login", params = {"login_challenge", "username", "password"})
    public String doLogin(@RequestParam String login_challenge,
                          @RequestParam String username,
                          @RequestParam String password,
                          @RequestParam(defaultValue = "false") boolean rememberMe,
                          HttpSession session,
    RedirectAttributes redirectModel, Model model) {
        redirectModel.addAttribute("login_challenge", login_challenge);
        redirectModel.addAttribute("username", username);
        redirectModel.addAttribute("rememberMe", rememberMe);
        session.setAttribute("rememberMe", rememberMe);
        if(username.trim().isEmpty()) {
            redirectModel.addAttribute("errorMsg", "Username is mandatory!");
            return "redirect:/login";
        }
        if(password.trim().isEmpty()) {
            redirectModel.addAttribute("errorMsg", "Password is mandatory!");
            return "redirect:/login";
        }
        //DirectLogin username="robert.xuk.x@example.com",password="5232e7",consumer_key="yp5tgl0thzjj1jk0sobqljpxyo514dsjvxoe1ngy"
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization",
                "DirectLogin username=\""+username+"\",password=\""+password+"\",consumer_key=\""+consumerKey+"\""
        );
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<DirectLoginResponse> tokenResponse = restTemplate.exchange(directLoginUrl, HttpMethod.POST, entity, DirectLoginResponse.class);

            AcceptLoginRequest acceptLoginRequest = new AcceptLoginRequest();
            acceptLoginRequest.setSubject(username);
            acceptLoginRequest.remember(rememberMe);
            // rememberMe for 1 hour.
            acceptLoginRequest.rememberFor(3600L);
            CompletedRequest response = hydraAdmin.acceptLoginRequest(login_challenge, acceptLoginRequest);
            String directLoginToken = tokenResponse.getBody().getToken();
            session.setAttribute("directLoginToken", directLoginToken);

            {// validate consentId
                String consentId = (String) session.getAttribute("consent_id");
                HttpEntity<String> body = new HttpEntity<>(buildDirectLoginHeader(session));
                restTemplate.exchange(getConsentUrl.replace("CONSENT_ID", consentId), HttpMethod.GET, body, Map.class);
            }
            {// validate bankId
                String bankId = (String) session.getAttribute("bank_id");
                HttpEntity<String> body = new HttpEntity<>(buildDirectLoginHeader(session));
                restTemplate.exchange(getBankUrl.replace("BANK_ID", bankId), HttpMethod.GET, body, Map.class);
            }

            return "redirect:" + response.getRedirectTo();
        } catch (HttpClientErrorException e) {
            String errorMsg = e.getMessage().replaceFirst(".*?(OBP-\\d+.*?)\".+", "$1");
            model.addAttribute("errorMsg", errorMsg + ". Please supply validate value!");
            return "error";
        } catch (Exception e) {
            model.addAttribute("errorMsg", "Unknown Error!");
            logger.error("Throw error when do direct login.", e);
            return "error";
        }

    }

    private static final Pattern CONSENT_ID_PATTERN = Pattern.compile(".*?consent_id=([^&$]*).*");
    private static final Pattern BANK_ID_PATTERN = Pattern.compile(".*?bank_id=([^&$]*).*");

    /**
     * get consent_id query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getConsentId(String authRequestUrl) {
        Matcher matcher = CONSENT_ID_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * get bank_id query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getBankId(String authRequestUrl) {
        Matcher matcher = BANK_ID_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
}
