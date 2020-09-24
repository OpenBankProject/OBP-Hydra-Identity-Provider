package com.openbankproject.oauth2.controller;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.AcceptConsentRequest;
import sh.ory.hydra.model.CompletedRequest;
import sh.ory.hydra.model.ConsentRequest;
import sh.ory.hydra.model.ConsentRequestSession;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@Controller
public class ConsentController {
    @Value("${oauth2.public_url}/oauth2/auth?")
    private String hydraLoginUrl;

    @Value("${obp.base_url}/obp/v4.0.0/users/current")
    private String currentUserUrl;

    @Value("${consumer_key}")
    private String consumerKey;

    @Value("${obp.base_url}")
    private String obpBaseUrl;

    @Value("${oauth2.allowed.standard.flow:false}")
    private boolean allowedStandardFlow;

    @Resource
    private AdminApi adminApi;

    //redirect by hydra to consent process
    @GetMapping(value="/consent", params = "consent_challenge")
    public String consentFromHydra(@RequestParam String consent_challenge, HttpSession session, Model model) throws ApiException {
        String bankId = (String) session.getAttribute("bank_id");
        model.addAttribute("obp_url", obpBaseUrl);
        if(bankId == null && !allowedStandardFlow) {
            model.addAttribute("errorMsg", "You can't go to this page directly, must redirect from hydra.");
            return "error";
        }

        String scope = (String) session.getAttribute("scope");
        String consentId = (String) session.getAttribute("consent_id");
        Boolean rememberMe = (Boolean) session.getAttribute("rememberMe");
        session.invalidate();

        ConsentRequest consentRequest = adminApi.getConsentRequest(consent_challenge);
        String username = consentRequest.getSubject();
        // login before and checked rememberMe.
        if(consentRequest.getSkip()) {
            AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
            acceptConsentRequest.setGrantScope(consentRequest.getRequestedScope());
            acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
            ConsentRequestSession hydraSession = buildConsentRequestSession(bankId, consentId, username);
            acceptConsentRequest.setSession(hydraSession);

            CompletedRequest acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
            return "redirect:" + acceptConsentResponse.getRedirectTo();
        } else if(bankId != null){
            AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
            String[] scopesArray = StringUtils.split(scope, '+');
            List<String> scopeList = Arrays.asList(scopesArray);
            acceptConsentRequest.setGrantScope(scopeList);
            acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
            acceptConsentRequest.setRemember(rememberMe);
            acceptConsentRequest.setRememberFor(3600L);

            ConsentRequestSession hydraSession = buildConsentRequestSession(bankId, consentId, username);
            acceptConsentRequest.setSession(hydraSession);

            CompletedRequest acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
            return "redirect:" + acceptConsentResponse.getRedirectTo();
        } else {
            model.addAttribute("consent_challenge", consent_challenge);
            model.addAttribute("scopes", consentRequest.getRequestedScope());
            return "consent";
        }
    }
    @PostMapping(value="/consent", params = "consent_challenge")
    public String confirmConsents(@RequestParam String consent_challenge, @RequestParam List<String> scopes, @RequestParam(defaultValue = "false") boolean rememberMe) throws ApiException {
        ConsentRequest consentRequest = adminApi.getConsentRequest(consent_challenge);
        String username = consentRequest.getSubject();
        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();

        acceptConsentRequest.setGrantScope(scopes);
        acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
        acceptConsentRequest.setRemember(rememberMe);
        acceptConsentRequest.setRememberFor(3600L);

        ConsentRequestSession hydraSession = buildConsentRequestSession(null, null, username);
        acceptConsentRequest.setSession(hydraSession);

        CompletedRequest acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
        return "redirect:" + acceptConsentResponse.getRedirectTo();
    }

    private ConsentRequestSession buildConsentRequestSession(String bankId, String consentId, String username) {
        ConsentRequestSession hydraSession = new ConsentRequestSession();

        { // prepare id_token content
            HashMap<String, Object> idTokenValues = new HashMap<>();
            idTokenValues.put("given_name", username);
            idTokenValues.put("family_name", username);
            idTokenValues.put("name", username);

            hydraSession.setIdToken(idTokenValues);
        }
        { // prepare access_token content
            HashMap<String, Object> accessToken = new HashMap<>();
            accessToken.put("bank_id", bankId);
            accessToken.put("consent_id", consentId);

            hydraSession.accessToken(accessToken);
        }
        return hydraSession;
    }
}
