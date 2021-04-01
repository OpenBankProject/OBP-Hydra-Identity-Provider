package com.openbankproject;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.digest.DigestUtils;

import java.text.ParseException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class JwsUtil {

    public static void main(String[] args) {
        System.out.println(createJws());
    }

    public static String createJws() {
        String pemEncodedRSAPrivateKey =
                "";

        String pemEncodedCertificate =
                "";

        String httpBody =
                "{\n" +
                "\"instructedAmount\": {\"currency\": \"EUR\", \"amount\": \"123.50\"},\n" +
                "\"debtorAccount\": {\"iban\": \"DE40100100103307118608\"},\n" +
                "\"creditorName\": \"Merchant123\",\n" +
                "\"creditorAccount\": {\"iban\": \"DE02100100109307118603\"},\n" +
                "\"remittanceInformationUnstructured\": \"Ref Number Merchant\"\n" +
                "}\n";

        String sigD = "{\n" +
                "\"pars\": [\n" +
                "\"(request-target)\",\n" +
                "\"host\",\n" +
                "\"content-type\",\n" +
                "\"psu-ip-address\",\n" +
                "\"psu-geo-location\",\n" +
                "\"digest\"\n" +
                "],\n" +
                "\"mId\": \"http://uri.etsi.org/19182/HttpHeaders\"\n" +
                "}\n";

        // We create the time in next format: '2011-12-03T10:15:30Z' 
        String sigT = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_ZONED_DATE_TIME);
        Set<String> criticalParams = getCriticalHeaders();
        JWK jwk  = null;
        RSASSASigner signer  = null;;
        try {
            jwk = JWK.parseFromPEMEncodedObjects(pemEncodedRSAPrivateKey);
            RSAKey rsaJWK  = jwk.toRSAKey();
            signer = new RSASSASigner(rsaJWK);
            // Create RSA-signer with the private key
        } catch (JOSEException e) {
            e.printStackTrace();
        }


        JWSHeader jwsProtectedHeader = null;
        try {
            criticalParams.addAll(getDeferredCriticalHeaders());
            jwsProtectedHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .base64URLEncodePayload(false)
                    .x509CertSHA256Thumbprint(jwk.computeThumbprint())
                    .criticalParams(criticalParams)
                    .customParam("sigT", sigT)
                    .customParam("sigD", JSONObjectUtils.parse(sigD))
                    .build();
        } catch (JOSEException | ParseException e) {
            e.printStackTrace();
        }
        
        String digest = computeDigest(httpBody);
        Payload detachedPayload = new Payload(
                "(request-target): post /berlin-group/v1.3/payments/sepa-credit-transfers\n" +
                        "host: api.testbank.com\n" +
                        "content-type: application/json\n" +
                        "psu-ip-address: 192.168.8.78\n" +
                        "psu-geo-location: GEO:52.506931,13.144558\n" +
                        "digest: SHA-256=" + digest + "\n"
        );

        JWSObject jwsObject = new JWSObject(jwsProtectedHeader, detachedPayload);
        {
            // Compute the RSA signature
            try {
                jwsObject.sign(signer);
            } catch (JOSEException e) {
                e.printStackTrace();
            }
        }
        boolean isDetached = true;
        String jws = jwsObject.serialize(isDetached);
        return jws;
    }
    

    // Base64 encoded sha256
    public static String computeDigest(String input) {
        String encodedString = Base64.getEncoder().encodeToString(DigestUtils.sha256(input));
        return encodedString; 
    }
    public static Boolean verifyDigestHeader(String headerValue, String httpBody) {
        if (headerValue.compareTo("SHA-256=" + computeDigest(httpBody)) == 0) {
            return true;
        }
        else {
            return false;
        }
    }

    public static Set<String> getDeferredCriticalHeaders() {
        Set<String> deferredCriticalHeaders = new HashSet<>();
        deferredCriticalHeaders.add("sigT");
        deferredCriticalHeaders.add("sigD");
        return deferredCriticalHeaders;
    }
    public static Set<String> getCriticalHeaders() {
        Set<String> criticalHeaders = new HashSet<>();
        criticalHeaders.add("b64");
        return criticalHeaders;
    }
    
}
