package com.openbankproject.oauth2;

import com.openbankproject.oauth2.model.DirectLoginResponse;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import sh.ory.hydra.ApiClient;
import sh.ory.hydra.Configuration;
import sh.ory.hydra.api.AdminApi;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Function;

import static com.openbankproject.oauth2.util.ControllerUtils.buildDirectLoginHeader;

@SpringBootApplication
public class Oauth2Application {
    private static final Logger logger = LoggerFactory.getLogger(Oauth2Application.class);
    
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
    public AdminApi hydraAdmin(SSLContext sslContext, TrustManager[] trustManagers) {
        ApiClient defaultClient = Configuration.getDefaultApiClient();
        defaultClient.setBasePath(hydraAdminUrl);

        // config MTLS for hydra client
        final OkHttpClient httpClient = defaultClient.getHttpClient();
        final OkHttpClient okHttpClient = httpClient.newBuilder()
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagers[0])
                .addInterceptor(new OkHttpClientLoggingInterceptor())
                .build();
        defaultClient.setHttpClient(okHttpClient);
        return new AdminApi(defaultClient);
    }

    public class OkHttpClientLoggingInterceptor implements Interceptor {

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();

            logger.info("=========================== request begin ================================================");
            logger.info("=== Method : {}", request.method());
            logger.info("=== URL : {}", request.url());
            logger.info("=== Headers : {}", StringUtils.join(request.headers(), "; "));
            logger.info("============================= request end ================================================");

            return chain.proceed(request);
        }
    }

    private void requestIntercept(org.apache.http.HttpRequest request, HttpContext httpContext) {
        String httpBody = getHttpBody(request).toString();
        logger.info("=========================== request begin ================================================");
        logger.info("=== Request Line : {}", request.getRequestLine());
        logger.info("=== Headers : {}", StringUtils.join(request.getAllHeaders(), "; "));
        logger.info("=== Request body: {}", httpBody);
        logger.info("============================= request end ================================================");
    }

    private StringBuilder getHttpBody(org.apache.http.HttpRequest request) {
        StringBuilder httpBody = new StringBuilder();
        if(request instanceof HttpEntityEnclosingRequest) {
            HttpEntityEnclosingRequest enclosingRequest = ((HttpEntityEnclosingRequest) request);
            org.apache.http.HttpEntity requestEntity = enclosingRequest.getEntity();

            try {
                InputStream inputStream =  requestEntity.getContent();
                try (Reader reader = new BufferedReader(new InputStreamReader
                        (inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
                    int c = 0;
                    while ((c = reader.read()) != -1) {
                        httpBody.append((char) c);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return httpBody;
    }

    /**
     * validate id function, (String url)-> Response json.
     * @param restTemplate
     * @return function
     */
    @Bean
    public Function<String, Map<String, Object>> idVerifier(RestTemplate restTemplate) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("DirectLogin",
                "username=\""+username+"\",password=\""+password+"\",consumer_key=\""+consumerKey+"\""
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
}
