package com.openbankproject.oauth2.util;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpSession;


public interface ControllerUtils {

   static HttpHeaders buildDirectLoginHeader(HttpSession session) {
        String directLoginToken = (String) session.getAttribute("directLoginToken");
        return buildDirectLoginHeader(directLoginToken);
    }
   static HttpHeaders buildDirectLoginHeader(String directLoginToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "DirectLogin token=\""+directLoginToken+"\"");
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}
