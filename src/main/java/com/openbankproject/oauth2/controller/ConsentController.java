package com.openbankproject.oauth2.controller;

import com.nimbusds.jose.util.X509CertUtils;
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
import sh.ory.hydra.model.*;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.openbankproject.oauth2.util.ControllerUtils.buildDirectLoginHeader;

@Controller
public class ConsentController {
    private static Logger logger = LoggerFactory.getLogger(ConsentController.class);

    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/accounts/ACCOUNT_ID/account-access")
    private String resetAccessViewUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/consents/CONSENT_ID")
    private String updateConsentStatusUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/accounts-held")
    private String getAccountsUrl;
    @Value("${oauth2.admin_url}/keys/${oauth2.broadcast_keys:hydra.jwt.access-token}")
    private String keySetUrl;

    @Resource
    private RestTemplate restTemplate;
    @Resource
    private AdminApi adminApi;

    private String idTokenSignHashAlg;

    @PostConstruct
    private void initiate() {
        final Map<String, List<Map<String, String>>> keySet = restTemplate.getForObject(keySetUrl, Map.class);

        final Optional<String> firstAlg = keySet.get("keys").stream()
                .filter(it -> "sig".equals(it.get("use")))
                .map(it -> it.get("alg"))
                .findFirst();
        if(firstAlg.isPresent()) {
            String idTokenSignAlg = firstAlg.get();
            // this rule: RS256 -> SHA-256
            idTokenSignHashAlg = idTokenSignAlg.replaceFirst(".*?(\\d+)$", "SHA-$1");
        } else {
            throw new IllegalStateException("Cant find id token sign jwk from " +  this.keySetUrl);
        }
    }

    //redirect by hydra to consent process
    @GetMapping(value="/consent", params = "consent_challenge")
    public String consentFromHydra(@RequestParam String consent_challenge, HttpSession session, Model model)  {
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
    public String resetAccessToViews(@RequestParam String consent_challenge, @RequestParam("accounts") String[] accountIs, HttpSession session, Model model) throws NoSuchAlgorithmException {
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

        final OAuth2Client client = consentRequest.getClient();
        final Map<String, String> metadata = ((Map<String, String>) client.getMetadata());
        String x5tS256 = null;
        if(metadata != null && metadata.get("client_certificate") != null) {
             x5tS256 = X509CertUtils.computeSHA256Thumbprint(X509CertUtils.parse(metadata.get("client_certificate"))).toString();
        }

        final String state = getState(consentRequest.getRequestUrl());
        final String sHash = buildHash(state);
        ConsentRequestSession hydraSession = buildConsentRequestSession(consentId, username, x5tS256, sHash);
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

    private ConsentRequestSession buildConsentRequestSession(String consentId, String username, String x5tS256, String sHash) {
        ConsentRequestSession hydraSession = new ConsentRequestSession();

        Map<String, String> x5tS256Map = new HashMap<>();
        x5tS256Map.put("x5t#S256", x5tS256);

        { // prepare id_token content
            HashMap<String, Object> idTokenValues = new HashMap<>();
            idTokenValues.put("given_name", username);
            idTokenValues.put("family_name", username);
            idTokenValues.put("name", username);
            idTokenValues.put("s_hash", sHash);
            if(x5tS256 != null) {
                idTokenValues.put("cnf", x5tS256Map);
            }

            hydraSession.setIdToken(idTokenValues);
        }
        { // prepare access_token content
            HashMap<String, Object> accessToken = new HashMap<>();
            accessToken.put("consent_id", consentId);
            if(x5tS256 != null) {
                accessToken.put("cnf", x5tS256Map);
            }

            hydraSession.accessToken(accessToken);
        }
        return hydraSession;
    }

    private static final Pattern STATE_PATTERN = Pattern.compile(".*?state=([^&$]*).*");
    /**
     * get bank_id query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getState(String authRequestUrl) {
        Matcher matcher = STATE_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
            return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * calculate the c_hash, at_hash, s_hash, the logic as follow:
     * 1. Using the hash algorithm specified in the alg claim in the ID Token header
     * 2. hash the octets of the ASCII representation of the code
     * 3. Base64url-encode the left-most half of the hash.
     *
     * @param str to calculate hash value
     * @return hash value
     */
    private String buildHash(String str) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(idTokenSignHashAlg);
        byte[] asciiValue = str.getBytes(StandardCharsets.US_ASCII);
        byte[] encodedHash = md.digest(asciiValue);
        byte[] halfOfEncodedHash = Arrays.copyOf(encodedHash, (encodedHash.length / 2));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(halfOfEncodedHash);
    }
}
