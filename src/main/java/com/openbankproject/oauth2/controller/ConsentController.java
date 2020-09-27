package com.openbankproject.oauth2.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.AcceptConsentRequest;
import sh.ory.hydra.model.CompletedRequest;
import sh.ory.hydra.model.ConsentRequest;
import sh.ory.hydra.model.ConsentRequestSession;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;

@Controller
public class ConsentController {

    @Value("${obp.base_url}")
    private String obpBaseUrl;

    @Resource
    private AdminApi adminApi;

    //redirect by hydra to consent process
    @GetMapping(value="/consent", params = "consent_challenge")
    public String consentFromHydra(@RequestParam String consent_challenge, HttpSession session, Model model) throws ApiException {
        model.addAttribute("obp_url", obpBaseUrl);

        Boolean rememberMe = (Boolean) session.getAttribute("rememberMe");
        String consentId = (String) session.getAttribute("consent_id");
        session.invalidate();

        ConsentRequest consentRequest = adminApi.getConsentRequest(consent_challenge);
        String username = consentRequest.getSubject();
        List<String> requestedScope = consentRequest.getRequestedScope();
        // login before and checked rememberMe.
        if(consentRequest.getSkip()) {
            AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
            acceptConsentRequest.setGrantScope(requestedScope);
            acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
            ConsentRequestSession hydraSession = buildConsentRequestSession(consentId, username);
            acceptConsentRequest.setSession(hydraSession);

            CompletedRequest acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
            return "redirect:" + acceptConsentResponse.getRedirectTo();
        } else {
            AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();

            acceptConsentRequest.setGrantScope(requestedScope);
            acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
            acceptConsentRequest.setRemember(rememberMe);
            acceptConsentRequest.setRememberFor(3600L);

            ConsentRequestSession hydraSession = buildConsentRequestSession(consentId, username);
            acceptConsentRequest.setSession(hydraSession);

            CompletedRequest acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
            return "redirect:" + acceptConsentResponse.getRedirectTo();
        }
    }

    private ConsentRequestSession buildConsentRequestSession(String consentId, String username) {
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
            accessToken.put("consent_id", consentId);

            hydraSession.accessToken(accessToken);
        }
        return hydraSession;
    }
}
