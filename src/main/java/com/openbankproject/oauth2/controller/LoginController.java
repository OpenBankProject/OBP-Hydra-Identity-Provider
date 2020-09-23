package com.openbankproject.oauth2.controller;

import com.openbankproject.oauth2.model.DirectLoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class LoginController {
    private static Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Value("${oauth2.public_url}/oauth2/auth?")
    private String hydraLoginUrl;

    @Value("${obp.base_url}/my/logins/direct")
    private String directLoginUrl;

    @Value("${consumer_key}")
    private String consumerKey;

    @Value("${oauth2.allowed.standard.flow:false}")
    private boolean allowedStandardFlow;

    @Resource
    private RestTemplate restTemplate;

    @Resource
    private AdminApi hydraAdmin;

    //show login page
    @GetMapping(value="/login", params = "login_challenge")
    public String loginFromHydra(@RequestParam String login_challenge,
                                 @RequestParam Map<String, String> queryParams,
                                 Model model, HttpSession session) throws ApiException {
        model.addAllAttributes(queryParams);
        if(session.getAttribute("bank_id") == null && !allowedStandardFlow) {
            model.addAttribute("errorMsg", "You can't go to this page directly, must redirect from hydra.");
            return "error";
        }
        try {
            LoginRequest loginRequest = hydraAdmin.getLoginRequest(login_challenge);
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

    //save bank_id to session, redirect to hydra login url
    @GetMapping(value="/login", params = {"client_id", "bank_id", "consent_id", "response_type=code", "scope", "redirect_uri", "state"})
    public String loginFromClient(@RequestParam String bank_id,
                                  @RequestParam String scope,
                                  @RequestParam String consent_id,
                                  @RequestParam Map<String, String> queryParams, HttpSession session) {
        // send scope value divide by "+", the received scope always divide by " ", So here recover it.
        String scopeValueStr = scope.replace(' ', '+');
        session.setAttribute("bank_id", bank_id);
        session.setAttribute("scope", scopeValueStr);
        session.setAttribute("consent_id", consent_id);

        // fix scope and redirect_uri value.
        queryParams.put("scope", scopeValueStr);
        queryParams.put("redirect_uri", encodeQueryParam(queryParams.get("redirect_uri")));

        String queryStr = queryParams.entrySet().stream()
                .map(it -> it.getKey() + "=" + it.getValue())
                .collect(Collectors.joining("&"));

        return "redirect:" + hydraLoginUrl + queryStr;
    }

    //do authentication
    @PostMapping(value="/login", params = {"login_challenge", "username", "password"})
    public String doLogin(@RequestParam String login_challenge,
                          @RequestParam String username,
                          @RequestParam String password,
                          @RequestParam(defaultValue = "false") boolean rememberMe,
                          HttpSession session,
    RedirectAttributes redirectModel) throws ApiException {
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
            session.setAttribute("directLoginToken", tokenResponse.getBody().getToken());
            return "redirect:" + response.getRedirectTo();
        } catch (HttpClientErrorException e) {
            String errorMsg = e.getMessage().replaceFirst(".*?(OBP-\\d+.*?)\".+", "$1");
            redirectModel.addAttribute("errorMsg", errorMsg);
            return "redirect:/login";
        } catch (Exception e) {
            redirectModel.addAttribute("errorMsg", "Unknown Error!");
            logger.error("Throw error when do direct login.", e);
            return "redirect:/login";
        }

    }

    private String encodeQueryParam(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException impossible) {
            logger.error("charset name is wrong", impossible);
            return null;
        }
    }
}
