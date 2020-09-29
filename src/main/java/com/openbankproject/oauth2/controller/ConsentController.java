package com.openbankproject.oauth2.controller;

import com.openbankproject.oauth2.model.AccessToViewRequest;
import com.openbankproject.oauth2.model.Accounts;
import org.apache.commons.lang3.ArrayUtils;
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
import org.springframework.web.client.RestTemplate;
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
import java.util.Map;

import static com.openbankproject.oauth2.util.ControllerUtils.buildDirectLoginHeader;

@Controller
public class ConsentController {
    private static Logger logger = LoggerFactory.getLogger(ConsentController.class);
    @Value("${obp.base_url}")
    private String obpBaseUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/accounts/ACCOUNT_ID/account-access")
    private String resetAccessViewUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/consents/CONSENT_ID")
    private String updateConsentStatusUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/accounts-held")
    private String getAccountsUrl;

    @Resource
    private RestTemplate restTemplate;
    @Resource
    private AdminApi adminApi;

    //redirect by hydra to consent process
    @GetMapping(value="/consent", params = "consent_challenge")
    public String consentFromHydra(@RequestParam String consent_challenge, HttpSession session, Model model)  {
        model.addAttribute("obp_url", obpBaseUrl);
        model.addAttribute("consent_challenge", consent_challenge);
        ConsentRequest consentRequest;
        try { // validate consent_challenge
             consentRequest = adminApi.getConsentRequest(consent_challenge);
        } catch (ApiException e) {
            logger.error("consent_challenge is wrong!", e);
            model.addAttribute("errorMsg", "consent_challenge is wrong!");
            return "error";
        }

        { // prepare account list
            String bankId = (String) session.getAttribute("bank_id");
            HttpHeaders headers = buildDirectLoginHeader(session);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<Accounts> accounts = restTemplate.exchange(getAccountsUrl.replace("BANK_ID", bankId), HttpMethod.GET, entity, Accounts.class);
            model.addAttribute("accounts", accounts.getBody().getAccounts());

            session.setAttribute("all_account_ids", accounts.getBody().accountIds());

            if(ArrayUtils.isEmpty(accounts.getBody().getAccounts())) {
                String clientUrl = consentRequest.getClient().getRedirectUris().get(0);
                model.addAttribute("client_url",clientUrl);
            }
        }
        String[] consents = consentRequest.getRequestedScope().stream()
                .filter(it -> !it.equals("openid") && !it.equals("offline"))
                .toArray(String[]::new);
        model.addAttribute("consents", consents);

        return "accounts";
    }
    @PostMapping(value="/reset_access_to_views", params = "consent_challenge")
    public String resetAccessToViews(@RequestParam String consent_challenge, @RequestParam("accounts") String[] accountIs, HttpSession session, Model model) {
        String bankId = (String) session.getAttribute("bank_id");

        ConsentRequest consentRequest;
        try {
            consentRequest = adminApi.getConsentRequest(consent_challenge);
        } catch (ApiException e) {
            logger.error("consent_challenge is wrong!", e);
            model.addAttribute("errorMsg", "consent_challenge is wrong!");
            return "error";
        }
        List<String> requestedScope = consentRequest.getRequestedScope();
        // exclude OAuth2 and OIDC scopes: "openid", "offline"
        String[] selectedObpScopes = requestedScope.stream()
                .filter(it -> !it.equals("openid") && !it.equals("offline"))
                .toArray(String[]::new);
        HttpHeaders headers = buildDirectLoginHeader(session);

        { // process selected accounts
            AccessToViewRequest body = new AccessToViewRequest(selectedObpScopes);
            HttpEntity<AccessToViewRequest> entity = new HttpEntity<>(body, headers);
            for (String accountId : accountIs) {
                String url = resetAccessViewUrl.replace("BANK_ID", bankId).replace("ACCOUNT_ID", accountId);
                restTemplate.exchange(url, HttpMethod.PUT, entity, HashMap.class);
            }
        }

        { // process not selected accounts
            String[] allAccountIds = (String[]) session.getAttribute("all_account_ids");
            String[] notSelectAccountIds = ArrayUtils.removeElements(allAccountIds, accountIs);
            AccessToViewRequest body = new AccessToViewRequest(ArrayUtils.EMPTY_STRING_ARRAY);
            HttpEntity<AccessToViewRequest> entity = new HttpEntity<>(body, headers);
            for (String accountId : notSelectAccountIds) {
                String url = resetAccessViewUrl.replace("BANK_ID", bankId).replace("ACCOUNT_ID", accountId);
                restTemplate.exchange(url, HttpMethod.PUT, entity, HashMap.class);
            }
        }
        { // update Consents status to AUTHORISED
            Map<String, String> body = new HashMap<>();
            body.put("status", "AUTHORISED");
            HttpEntity<Map<String, String>> entity = new HttpEntity<>(body, headers);
            String consentId = (String) session.getAttribute("consent_id");
            String url = updateConsentStatusUrl.replace("CONSENT_ID", consentId).replace("BANK_ID", bankId);

            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.PUT, entity, Map.class);
            if(response.getStatusCodeValue() == 200) {
                // do nothing
            } else if(response.getStatusCodeValue() == 202) {
                // TODO do SCA challenge
            } else {
                // TODO impossible error.
            }
        }
        Boolean rememberMe = (Boolean) session.getAttribute("rememberMe");
        String consentId = (String) session.getAttribute("consent_id");


        String username = consentRequest.getSubject();

        AcceptConsentRequest acceptConsentRequest = new AcceptConsentRequest();
        acceptConsentRequest.setGrantScope(requestedScope);
        acceptConsentRequest.setGrantAccessTokenAudience(consentRequest.getRequestedAccessTokenAudience());
        ConsentRequestSession hydraSession = buildConsentRequestSession(consentId, username);
        acceptConsentRequest.setSession(hydraSession);
        // login before and checked rememberMe.
        if(!consentRequest.getSkip()) {
            acceptConsentRequest.setRemember(rememberMe);
            acceptConsentRequest.setRememberFor(3600L);
        }
        CompletedRequest acceptConsentResponse = null;
        try {
            acceptConsentResponse = adminApi.acceptConsentRequest(consent_challenge, acceptConsentRequest);
        } catch (ApiException e) {
            logger.error("Accept consent request fail.", e);
            model.addAttribute("Accept consent request fail.", "consent_challenge is wrong!");
            return "error";
        }
        return "redirect:" + acceptConsentResponse.getRedirectTo();
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
