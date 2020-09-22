package com.openbankproject.oauth2.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import sh.ory.hydra.ApiException;
import sh.ory.hydra.api.AdminApi;
import sh.ory.hydra.model.CompletedRequest;

import javax.annotation.Resource;

@Controller
public class LogoutController {
    private static Logger logger = LoggerFactory.getLogger(LogoutController.class);

    @Resource
    private AdminApi hydraAdmin;

    @GetMapping(value={"/logout"}, params = "logout_challenge")
    public String logout(@RequestParam String logout_challenge, Model model) {
        try {
            // validate logout_challenge value
            this.hydraAdmin.getLogoutRequest(logout_challenge);
            CompletedRequest completedRequest = hydraAdmin.acceptLogoutRequest(logout_challenge);
            return "redirect:" + completedRequest.getRedirectTo();
        } catch (ApiException e) {
            logger.error("Logout fail, logout_challenge="+logout_challenge, e);
            model.addAttribute("errorMsg", "Parameter logout_challenge is not correct, hint: You can't go to this page directly, must redirect from hydra.");
            return "error";
        }
    }
}
