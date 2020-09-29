package com.openbankproject.oauth2;

import com.openbankproject.oauth2.model.DirectLoginResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import sh.ory.hydra.ApiClient;
import sh.ory.hydra.Configuration;
import sh.ory.hydra.api.AdminApi;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;

import static com.openbankproject.oauth2.util.ControllerUtils.buildDirectLoginHeader;

@SpringBootApplication
public class Oauth2Application {
    @Value("${oauth2.admin_url}")
    private String hydraAdminUrl;
    @Value("${identity_provider.user.username}")
    private String username;
    @Value("${identity_provider.user.password}")
    private String password;
    @Value("${consumer_key}")
    private String consumerKey;

    @Value("${obp.base_url}/my/logins/direct")
    private String directLoginUrl;

    public static void main(String[] args) {
        SpringApplication.run(Oauth2Application.class, args);
    }

    @Bean
    public AdminApi hydraAdmin() {
        ApiClient defaultClient = Configuration.getDefaultApiClient();
        defaultClient.setBasePath(hydraAdminUrl);
        return new AdminApi(defaultClient);
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {

        return builder
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(30))
                .interceptors(this::headerIntercept)
                .build();
    }

    /**
     * validate id function, (String url)-> Response json.
     * @param restTemplate
     * @return function
     */
    @Bean
    public Function<String, Map<String, Object>> idVerifier(RestTemplate restTemplate) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization",
                "DirectLogin username=\""+username+"\",password=\""+password+"\",consumer_key=\""+consumerKey+"\""
        );
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<DirectLoginResponse> tokenResponse = restTemplate.exchange(directLoginUrl, HttpMethod.POST, entity, DirectLoginResponse.class);

        String directLoginToken = tokenResponse.getBody().getToken();
        HttpEntity<String> requestEntity = new HttpEntity<>(buildDirectLoginHeader(directLoginToken));

        return (String url) -> {
            try{
                return restTemplate.exchange(url, HttpMethod.GET, requestEntity, Map.class).getBody();
            } catch (HttpClientErrorException e) {
                String errorMsg = e.getMessage().replaceFirst(".*?(OBP-\\d+.*?)\".+", "$1");
                throw new RuntimeException(errorMsg, e);
            }
        };
    }

    private ClientHttpResponse headerIntercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        HttpHeaders headers = request.getHeaders();
        if(headers.getContentType() == null) {
            headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        }
        return execution.execute(request, body);
    }
}
