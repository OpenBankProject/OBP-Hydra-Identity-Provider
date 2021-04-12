package com.openbankproject.oauth2.controller;

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
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.AcceptLoginRequest;
import sh.ory.hydra.model.CompletedRequest;
import sh.ory.hydra.model.LoginRequest;

import javax.annotation.Resource;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Controller
public class LoginController implements ServletContextAware {
    private static Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Value("${obp.base_url}")
    private String obpBaseUrl;

    @Value("${obp.base_url}/my/logins/direct")
    private String directLoginUrl;

    @Value("${endpoint.path.prefix}/account-access-consents/CONSENT_ID")
    private String getConsentUrl;
    @Value("${obp.base_url}/obp/v4.0.0/banks/BANK_ID")
    private String getBankUrl;

    @Value("${consumer_key}")
    private String consumerKey;

    @Resource
    private RestTemplate restTemplate;

    @Resource
    private AdminApi hydraAdmin;
    @Resource
    private Function<String, Map<String, Object>> idVerifier;

    @Value("${button.background_color:#c9302c}")
    private String buttonBackgroundColor;
    @Value("${button.hover.background_color:#b92c28}")
    private String buttonHoverBackgroundColor;

    /**
     * initiate global variable
     * @param servletContext
     */
    @Override
    public void setServletContext(ServletContext servletContext) {
        servletContext.setAttribute("obp_url", obpBaseUrl);
    }

    //show login page
    @GetMapping(value="/login", params = "login_challenge")
    public String loginFromHydra(@RequestParam String login_challenge,
                                 Model model, HttpSession session){
        model.addAttribute("login_challenge", login_challenge);
        model.addAttribute("buttonBackgroundColor", buttonBackgroundColor);
        model.addAttribute("buttonHoverBackgroundColor", buttonHoverBackgroundColor);

        try {
            LoginRequest loginRequest = hydraAdmin.getLoginRequest(login_challenge);
            String requestUrl = loginRequest.getRequestUrl();
            String consentId = getConsentId(requestUrl);
            String bankId = getBankId(requestUrl);
            String iban = getIban(requestUrl);
            String recurringIndicator = getRecurringIndicator(requestUrl);
            String frequencyPerDay = getFrequencyPerDay(requestUrl);
            String expirationTime = getExpirationTime(requestUrl);
            String apiStandard = getApiStandard(requestUrl);
            final List<String> acrValues = loginRequest.getOidcContext().getAcrValues();
            if(bankId == null) {
                model.addAttribute("errorMsg", "Query parameter `bank_id` is mandatory! ");
                return "error";
            }
            if(consentId  == null) {
                final String createConsentUrl = getConsentUrl.replace("/CONSENT_ID", "");
                model.addAttribute(
                        "errorMsg", "Query parameter `consent_id` is mandatory! " +
                        "Hint: create client_credentials accessToken, create Account Access Consents by call endpoint `CreateAccountAccessConsents` (" +
                         createConsentUrl +
                         "), " +
                         "with header Authorization: Authorization: Bearer <accessToken>");
                return "error";
            }
            // TODO acr value should do more validation
//            if(CollectionUtils.isEmpty(acrValues)) {
//                model.addAttribute("errorMsg", "Query parameter `acr_values` is mandatory! ");
//                return "error";
//            }
            // TODO in order make old consumer works, the request and request_uri are optional.
//            if(!requestUrl.contains("request") && !requestUrl.contains("request_uri")) {
//                model.addAttribute(
//                        "errorMsg", "Query parameter `request` and `request_uri` at least one must be supplied! " +
//                                "Hint: please reference <a href=\"https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests\">Passing Request Parameters as JWTs</a>");
//                return "error";
//            }

            try {
                if(!apiStandard.equalsIgnoreCase("BerlinGroup"))
                {// validate consentId
                    Map<String, Object> responseBody = idVerifier.apply(getConsentUrl.replace("CONSENT_ID", consentId));
                    Map<String, Object> data = ((Map<String, Object>) responseBody.get("Data"));
                    if(data == null || data.isEmpty()) {
                        model.addAttribute("errorMsg", "Consent content have no required Data field");
                        return "error";
                    }

                    String status = ((String) data.get("Status"));
                    if(!"AWAITINGAUTHORISATION".equals(status)) {
                        model.addAttribute("errorMsg", "The Consent status should be AWAITINGAUTHORISATION, but current status is " + status);
                        return "error";
                    }
                }
                {// validate bankId
                    idVerifier.apply(getBankUrl.replace("BANK_ID", bankId));
                }
            } catch (Exception e) {
                model.addAttribute("errorMsg", e.getMessage());
                return "error";
            }

            session.setAttribute("consent_id", consentId);
            session.setAttribute("bank_id", bankId);
            session.setAttribute("iban", iban);
            session.setAttribute("recurring_indicator", recurringIndicator);
            session.setAttribute("frequency_per_day", frequencyPerDay);
            session.setAttribute("expiration_time", expirationTime);
            session.setAttribute("api_standard", apiStandard);
            session.setAttribute("acr_values", acrValues);

            // login before and checked rememberMe.
            if(loginRequest.getSkip() && session.getAttribute("directLoginToken") != null) {
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

            List<String> acrValues = (List<String>) session.getAttribute("acr_values");
            if(!CollectionUtils.isEmpty(acrValues)) {
                acceptLoginRequest.setAcr(acrValues.get(0));
            }

            // rememberMe for 1 hour.
            acceptLoginRequest.rememberFor(3600L);
            CompletedRequest response = hydraAdmin.acceptLoginRequest(login_challenge, acceptLoginRequest);
            String directLoginToken = tokenResponse.getBody().getToken();
            session.setAttribute("directLoginToken", directLoginToken);

            return "redirect:" + response.getRedirectTo();
        } catch (HttpClientErrorException e) {
            String errorMsg = e.getMessage().replaceFirst(".*?(OBP-\\d+.*?)\".+", "$1");
            model.addAttribute("errorMsg", errorMsg);
            return "error";
        } catch (Exception e) {
            model.addAttribute("errorMsg", "Unknown Error!");
            logger.error("Throw error when do direct login.", e);
            return "error";
        }

    }

    private static final Pattern CONSENT_ID_PATTERN = Pattern.compile(".*?consent_id=([^&$]*).*");
    private static final Pattern BANK_ID_PATTERN = Pattern.compile(".*?bank_id=([^&$]*).*");
    private static final Pattern IBAN_PATTERN = Pattern.compile(".*?iban=([^&$]*).*");
    private static final Pattern RECURRING_INDICATOR_PATTERN = Pattern.compile(".*?recurring_indicator=([^&$]*).*");
    private static final Pattern FREQUENCY_PER_DAY_PATTERN = Pattern.compile(".*?frequency_per_day=([^&$]*).*");
    private static final Pattern EXPIRATION_TIME_PATTERN = Pattern.compile(".*?expiration_time=([^&$]*).*");
    private static final Pattern API_STANDARD_PATTERN = Pattern.compile(".*?api_standard=([^&$]*).*");

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
    /**
     * get bank_id query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getIban(String authRequestUrl) {
        Matcher matcher = IBAN_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * get recurring_indicator query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getRecurringIndicator(String authRequestUrl) {
        Matcher matcher = RECURRING_INDICATOR_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * get frequency_per_day query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getFrequencyPerDay(String authRequestUrl) {
        Matcher matcher = FREQUENCY_PER_DAY_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * get expiration_time query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getExpirationTime(String authRequestUrl) {
        Matcher matcher = EXPIRATION_TIME_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
    /**
     * get api_standard query parameter from auth request url
     * @param authRequestUrl
     * @return
     */
    private String getApiStandard(String authRequestUrl) {
        Matcher matcher = API_STANDARD_PATTERN.matcher(authRequestUrl);
        if(matcher.matches()) {
           return matcher.replaceFirst("$1");
        } else {
            return null;
        }
    }
}
