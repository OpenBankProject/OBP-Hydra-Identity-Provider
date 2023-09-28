package com.openbankproject.oauth2.controller;

import com.nimbusds.jose.util.X509CertUtils;
import com.openbankproject.oauth2.model.AccessToViewRequest;
import com.openbankproject.oauth2.model.Accounts;
import com.openbankproject.oauth2.model.ConsentsInfo;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.*;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
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
    @Value("${obp.base_url}/berlin-group/v1.3/consents")
    private String createBerlinGroupConsentsUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID/my/consents")
    private String getConsentsUrl;
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID/authorisations")
    private String startConsentAuthorisation;
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID/authorisations/AUTHORISATION_ID")
    private String updateConsentsPsuData;
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID")
    private String deleteConsentBerlinGroup;
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID/status")
    private String getConsentStatus;
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID/authorisations/AUTHORISATION_ID")
    private String getConsentScaStatus;
    
    @Value("${obp.base_url}/obp/v5.1.0/banks/BANK_ID/consents/CONSENT_ID/challenge")
    private String answerConsentChallenge;
    
    @Value("${obp.base_url}/obp/v5.1.0/consumer/consent-requests/CONSENT_REQUEST_ID")
    private String getConsentRequest;
    
    @Value("${obp.base_url}/obp/v5.1.0/consumer/consent-requests/CONSENT_REQUEST_ID/EMAIL/consents")
    private String createConsentByConsentRequestIdEmail;
    
    @Value("${obp.base_url}/obp/v5.1.0/consumer/consent-requests/CONSENT_REQUEST_ID/IMPLICIT/consents")
    private String createConsentByConsentRequestIdImplicit;
    
    @Value("${obp.base_url}/berlin-group/v1.3/consents/CONSENT_ID/authorisations")
    private String getConsentAuthorisation;
    @Value("${oauth2.admin_url}/keys/${oauth2.broadcast_keys:hydra.jwt.access-token}")
    private String keySetUrl;
    @Value("${show_unhandled_errors:false}")
    private boolean showUnhandledErrors;

    @Value("${logo.bank.enabled:false}")
    private String showBankLogo;
    @Value("${logo.bank.url:#}")
    private String bankLogoUrl;

    @Value("${obp.base_url:#}")
    private String obpBaseUrl;

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
        try {
            model.addAttribute("consent_challenge", consent_challenge);
            ConsentRequest consentRequest;
            try { // validate consent_challenge
                consentRequest = adminApi.getConsentRequest(consent_challenge);
            } catch (ApiException e) {
                logger.error("consent_challenge is wrong!", e);
                model.addAttribute("errorMsg", "consent_challenge is wrong!");
                return "error";
            }
            
            String bankId = (String) session.getAttribute("bank_id");
            String consentId = (String) session.getAttribute("consent_id");
            
            // OpenID Connect Flow
            if(consentId == null) {
                logger.info("OpenID Connect Flow");
                return "redirect:" + obpBaseUrl + "/consent-screen?consent_challenge=" + consent_challenge;
            }
            
            if(consentId.equalsIgnoreCase("Utility-List-Consents")) {
                HttpHeaders headers = buildDirectLoginHeader(session);
                HttpEntity<String> entity = new HttpEntity<>(headers);
                ResponseEntity<ConsentsInfo> consents = restTemplate.exchange(getConsentsUrl.replace("BANK_ID", bankId), HttpMethod.GET, entity, ConsentsInfo.class);
                model.addAttribute("consents", consents.getBody().getConsents());
                return "consents";
            }

            String[] consents = consentRequest.getRequestedScope().stream()
                    .filter(it -> !it.equals("openid") && !it.equals("offline"))
                    .toArray(String[]::new);
            { // prepare account list
                String apiStandard = (String) session.getAttribute("api_standard");
                model.addAttribute("apiStandard", apiStandard);
                HttpHeaders headers = buildDirectLoginHeader(session);
                HttpEntity<String> entity = new HttpEntity<>(headers);
                ResponseEntity<Accounts> accounts = restTemplate.exchange(getAccountsUrl.replace("BANK_ID", bankId), HttpMethod.GET, entity, Accounts.class);
                if(apiStandard.equalsIgnoreCase("BerlinGroup")) {
                    String[] ibans = ((String) session.getAttribute("iban")).split(",");
                    model.addAttribute("accounts", accounts.getBody().getIbanAccounts(ibans));
                    session.setAttribute("all_account_ids", accounts.getBody().accountIdsWithIban());
                    session.setAttribute("all_account_ibans", accounts.getBody().getIbans());
                    session.setAttribute("all_accounts_id_to_iban", accounts.getBody().getIdtoIbanMap());
                    if(ArrayUtils.isEmpty(accounts.getBody().getIbanAccounts())) {
                        String clientUrl = consentRequest.getClient().getRedirectUris().get(0);
                        model.addAttribute("client_url",clientUrl);
                    }
                } else if(apiStandard.equalsIgnoreCase("OBP")) {

                    // Get consent info
                    String consentRequestId = (String) session.getAttribute("consent_request_id");
                    ResponseEntity<Map> consentInfo = restTemplate.exchange(getConsentRequest.replace("CONSENT_REQUEST_ID", consentRequestId), HttpMethod.GET, entity, Map.class);
                    Map<String, Boolean> payload = (Map<String, Boolean>) consentInfo.getBody().get("payload");
                    Boolean everything = (Boolean)payload.get("everything");
                    if(everything) {
                        ArrayList<String> arrayList = new ArrayList<String>(Arrays.asList(consents));
                        arrayList.add("everything");
                        consents = arrayList.toArray(consents);
                    }
                    
                    model.addAttribute("accounts", accounts.getBody().getAllAccounts());
                    session.setAttribute("all_account_ids", accounts.getBody().accountIdsWithIban());
                    session.setAttribute("all_account_ibans", accounts.getBody().getIbans());
                    session.setAttribute("all_accounts_id_to_iban", accounts.getBody().getIdtoIbanMap());
                    if(ArrayUtils.isEmpty(accounts.getBody().getIbanAccounts())) {
                        String clientUrl = consentRequest.getClient().getRedirectUris().get(0);
                        model.addAttribute("client_url",clientUrl);
                    }
                } 
                else {
                    model.addAttribute("accounts", accounts.getBody().getAccounts());
                    session.setAttribute("all_account_ids", accounts.getBody().accountIds());
                    if(ArrayUtils.isEmpty(accounts.getBody().getAccounts())) {
                        String clientUrl = consentRequest.getClient().getRedirectUris().get(0);
                        model.addAttribute("client_url",clientUrl);
                    }
                }
            }
            
            model.addAttribute("consents", consents);
            model.addAttribute("showBankLogo", showBankLogo);
            model.addAttribute("obpBaseUrl", obpBaseUrl);
            model.addAttribute("bankLogoUrl", bankLogoUrl);

            return "accounts";
        } catch (Exception unhandledException) {
            logger.error("Error: ", unhandledException);
            if(showUnhandledErrors) model.addAttribute("errorMsg", unhandledException);
            else model.addAttribute("errorMsg", "Internal Server Error");
            return "error";
        }
    }


    @PostMapping(value="/sca2", params = {"consent_challenge", "password"})
    public String doLogin(@RequestParam String consent_challenge,
                          @RequestParam String password,
                          HttpSession session,
                          RedirectAttributes redirectModel, Model model) {
        try {
            model.addAttribute("showBankLogo", showBankLogo);
            model.addAttribute("obpBaseUrl", obpBaseUrl);
            model.addAttribute("bankLogoUrl", bankLogoUrl);
            String apiStandard = (String) session.getAttribute("api_standard");
            HttpHeaders headers = buildDirectLoginHeader(session);
            String consentId = (String) session.getAttribute("consent_id");
            Map<String, String> body2 = new HashMap<>();
            String url = "";
            HttpMethod method = HttpMethod.PUT;
            if(apiStandard.equalsIgnoreCase("BerlinGroup")){
                body2.put("scaAuthenticationData", password);
                String authorizationId = (String) session.getAttribute("authorizationId");
                url = updateConsentsPsuData.replace("CONSENT_ID", consentId)
                        .replace("AUTHORISATION_ID", authorizationId);
                method = HttpMethod.PUT;
            } else if(apiStandard.equalsIgnoreCase("OBP")) {
                body2.put("answer", password);
                String bankId = (String) session.getAttribute("bank_id");
                url = answerConsentChallenge.replace("CONSENT_ID", consentId)
                        .replace("BANK_ID", bankId);
                method = HttpMethod.POST;
                
            } else {
                //
            }
            HttpEntity<Map<String, String>> entity2 = new HttpEntity<>(body2, headers);
            try {
                ResponseEntity<Map> response2 = restTemplate.exchange(url, method, entity2, Map.class);
                String redirect = (String) session.getAttribute("acceptConsentResponse.getRedirectTo()");
                logger.info("redirect:" + redirect);
                return "redirect:" + redirect;
            } catch (Exception e) {
                String error = "Sorry! The one time password (OTP) you supplied is incorrect.";
                logger.error(error, e);
                model.addAttribute("errorMsg", error);
                return "sca_modal";
            }
        } catch (Exception unhandledException) {
            logger.error("Error: ", unhandledException);
            if(showUnhandledErrors) model.addAttribute("errorMsg", unhandledException); 
            else model.addAttribute("errorMsg", "Internal Server Error");
            return "error";
        }
    }
    
    
    @PostMapping(value="/revoke_consents", params = "consent_challenge")
    public String revokeConsents(@RequestParam String consent_challenge,
                                     @RequestParam(value="consents", required = false) String[] consentIds,
                                     @RequestParam(value="deny",required = false) String deny,
                                     HttpSession session, Model model) throws NoSuchAlgorithmException, ApiException {
        if(StringUtils.isNotBlank(deny)) {
            final RejectRequest rejectRequest = new RejectRequest().error("access_denied").errorDescription("The resource owner denied the request");
            final CompletedRequest completedRequest = adminApi.rejectConsentRequest(consent_challenge, rejectRequest);
            return "redirect:" + completedRequest.getRedirectTo();
        }
        if(ArrayUtils.isEmpty(consentIds)) {
            model.addAttribute("errorMsg", "consents field is mandatory!");
            return "error";
        }
        
        try { // Delete all selected consents
            HttpHeaders headers = buildDirectLoginHeader(session);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            for (String consentId : consentIds) {
                String url = deleteConsentBerlinGroup.replace("CONSENT_ID", consentId);
                ResponseEntity<Map> deletedConsent = restTemplate.exchange(url, HttpMethod.DELETE, entity, Map.class);
                logger.debug("ConsentID: " + consentId + " is deleted: " + deletedConsent.getStatusCodeValue());
            }
        } catch (Exception e) {
            logger.error("Cannot delete consents!", e);
            model.addAttribute("errorMsg", "Cannot delete consents!");
            return "error";
        }
        model.addAttribute("errorMsg", "All selected consents have been deleted!");
        return "error";
    }
    
    @PostMapping(value="/sca1", params = "consent_challenge")
    public String resetAccessToViews(@RequestParam String consent_challenge,
                                     @RequestParam(value="accounts", required = false) String[] accountIs,
                                     @RequestParam(value="deny",required = false) String deny,
                                     HttpSession session, Model model) throws NoSuchAlgorithmException, ApiException {
        try{
            model.addAttribute("showBankLogo", showBankLogo);
            model.addAttribute("obpBaseUrl", obpBaseUrl);
            model.addAttribute("bankLogoUrl", bankLogoUrl);
            if(StringUtils.isNotBlank(deny)) {
                final RejectRequest rejectRequest = new RejectRequest().error("access_denied").errorDescription("The resource owner denied the request");
                final CompletedRequest completedRequest = adminApi.rejectConsentRequest(consent_challenge, rejectRequest);
                return "redirect:" + completedRequest.getRedirectTo();
            }

            if(ArrayUtils.isEmpty(accountIs)) {
                model.addAttribute("errorMsg", "accounts field is mandatory!");
                return "error";
            }

            String bankId = (String) session.getAttribute("bank_id");
            String apiStandard = (String) session.getAttribute("api_standard");

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
            String[] allAccountIds = (String[]) session.getAttribute("all_account_ids");

            if(apiStandard.equalsIgnoreCase("BerlinGroup")){
                // Start consent authorization
                String consentId = (String) session.getAttribute("consent_id");
                Map<String, String> body2 = new HashMap<>();
                HttpEntity<Map<String, String>> entity = new HttpEntity<>(body2, headers);
                String url = startConsentAuthorisation.replace("CONSENT_ID", consentId);
                ResponseEntity<Map> response1 = restTemplate.exchange(url, HttpMethod.POST, entity, Map.class);
                Map<String, String> links = (Map<String, String>) response1.getBody().get("_links");
                String scaStatus = links.get("scaStatus");
                String[] parts = scaStatus.split("authorisations/");
                String authorizationId = parts[1];
                session.setAttribute("authorizationId", authorizationId);
            } else if(apiStandard.equalsIgnoreCase("OBP")){
                // Create Consent
                String consentRequestId = (String) session.getAttribute("consent_request_id");
                Map<String, String> body2 = new HashMap<>();
                HttpEntity<Map<String, String>> entity = new HttpEntity<>(body2, headers);
                String url = createConsentByConsentRequestIdImplicit
                        .replace("CONSENT_REQUEST_ID", consentRequestId);
                ResponseEntity<Map> responseCreateConsent = restTemplate.exchange(url, HttpMethod.POST, entity, Map.class);
                session.setAttribute("consent_id", responseCreateConsent.getBody().get("consent_id"));
            } else {
                { // process selected accounts
                    AccessToViewRequest body = new AccessToViewRequest(selectedObpScopes);
                    HttpEntity<AccessToViewRequest> entity = new HttpEntity<>(body, headers);

                    for (String accountId : accountIs) {
                        if(!ArrayUtils.contains(allAccountIds, accountId)) continue;
                        String url = resetAccessViewUrl.replace("BANK_ID", bankId).replace("ACCOUNT_ID", accountId);
                        restTemplate.exchange(url, HttpMethod.PUT, entity, HashMap.class);
                    }
                }

                { // process not selected accounts
                    String[] notSelectAccountIds = ArrayUtils.removeElements(allAccountIds, accountIs);
                    AccessToViewRequest body = new AccessToViewRequest(ArrayUtils.EMPTY_STRING_ARRAY);
                    HttpEntity<AccessToViewRequest> entity = new HttpEntity<>(body, headers);
                    for (String accountId : notSelectAccountIds) {
                        String url = resetAccessViewUrl.replace("BANK_ID", bankId).replace("ACCOUNT_ID", accountId);
                        restTemplate.exchange(url, HttpMethod.PUT, entity, HashMap.class);
                    }
                }

                // update Consents status to AUTHORISED
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
                logger.debug("client_certificate: " + metadata.get("client_certificate"));
                String pem = metadata.get("client_certificate");
                String decodedPem = URLDecoder.decode(pem,"UTF-8");
                logger.debug("before computing SHA256 thumbprint using parsedPem");
                if(X509CertUtils.parse(pem) == null) {
                    logger.debug("Use a decoded pem");
                    x5tS256 = X509CertUtils.computeSHA256Thumbprint(X509CertUtils.parse(decodedPem)).toString();
                } else {
                    logger.debug("Use a pem");
                    x5tS256 = X509CertUtils.computeSHA256Thumbprint(X509CertUtils.parse(pem)).toString();
                }
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

            if(apiStandard.equalsIgnoreCase("BerlinGroup")) {
                // Get status of the consent
                HttpEntity<String> entity = new HttpEntity<>(headers);
                ResponseEntity<Map> consents = restTemplate.exchange(getConsentStatus.replace("CONSENT_ID", consentId), HttpMethod.GET, entity, Map.class);
                model.addAttribute("consent_status", (String)consents.getBody().get("consentStatus"));

                // Get status of the authorization
                String authorizationId = (String)session.getAttribute("authorizationId");
                ResponseEntity<Map> authorization = restTemplate.exchange(getConsentScaStatus.replace("CONSENT_ID", consentId).replace("AUTHORISATION_ID", authorizationId), HttpMethod.GET, entity, Map.class);
                model.addAttribute("authorization_status", (String)authorization.getBody().get("scaStatus"));
               
                // Get consent authorization's ids
                ResponseEntity<Map> authorizationIds = restTemplate.exchange(getConsentAuthorisation.replace("CONSENT_ID", consentId), HttpMethod.GET, entity, Map.class);
                ArrayList<String> list = (ArrayList<String>)authorizationIds.getBody().get("authorisationIds");
                model.addAttribute("authorization_ids",  String.join(", ", list));
                
                model.addAttribute("consent_challenge", consent_challenge);
                session.setAttribute("acceptConsentResponse.getRedirectTo()", acceptConsentResponse.getRedirectTo());
                logger.info("acceptConsentResponse.getRedirectTo():" + acceptConsentResponse.getRedirectTo());
                return "sca_modal";
            } else if(apiStandard.equalsIgnoreCase("OBP")){
                model.addAttribute("consent_challenge", consent_challenge);
                session.setAttribute("acceptConsentResponse.getRedirectTo()", acceptConsentResponse.getRedirectTo());
                logger.info("acceptConsentResponse.getRedirectTo():" + acceptConsentResponse.getRedirectTo());
                return "sca_modal";
            } else {
                return "redirect:" + acceptConsentResponse.getRedirectTo();
            }
        } catch (Exception unhandledException) {
            logger.error("Error: ", unhandledException);
            if(showUnhandledErrors) model.addAttribute("errorMsg", unhandledException);
            else model.addAttribute("errorMsg", "Internal Server Error");
            return "error";
        }
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
            idTokenValues.put("consent_id", consentId);
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
