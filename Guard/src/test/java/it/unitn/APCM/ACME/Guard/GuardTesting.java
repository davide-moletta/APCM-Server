package it.unitn.APCM.ACME.Guard;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.TestMethodOrder;
//import org.junit.jupiter.api.Test;
import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;
import it.unitn.APCM.ACME.DBManager.DB_RESTApp;

import java.util.List;




/**
 * Testing Class for Guard component
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = Guard_RESTApp.class, 
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        useMainMethod = SpringBootTest.UseMainMethod.ALWAYS)
@TestMethodOrder(OrderAnnotation.class)
// @ActiveProfiles("test") // for application-test.properties
public class GuardTesting {

    @LocalServerPort
    private int port;
    RestTemplate rest = (new SecureRestTemplateConfig("Client_keystore.jks", "Client_truststore.jks")).secureRestTemplate();
    String email = "test2@acme.local";

    
    private ConfigurableApplicationContext application1Context;
    /* 
    @Test
    @Order(1)
    public void startApplications() {
        application1Context = new SpringApplicationBuilder(DB_RESTApp.class)
            .properties("server.port=8091", "spring.main.lazy-initialization=true")
            .profiles("DBManager")
            .run();
    }
*/
    private String loginFunc(String email, String psw){
        String credentials = "{\"email\": \""+ email + "\", \"password\":\""+ psw +"\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        String jwt = "";
        List<String> jwtlist = res.getHeaders().get("jwt");
        if (jwtlist != null) {
           jwt = jwtlist.get(0);
        }

        return jwt;
    }

    @Test
    @Order(1)
    public void login() throws Exception  {
        String credentials = "{\"email\": \"test2@acme.local\", \"password\":\"test\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
           
        String jwt = "";
        List<String> jwtlist = res.getHeaders().get("jwt");
        if (jwtlist != null) {
           jwt = jwtlist.get(0);
        }
        assertNotNull(jwt);
        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    @Test
    @Order(2)
    public void loginWrongPSW() throws Exception  {
        String credentials = "{\"email\": \"test2@acme.local\", \"password\":\"wrongPsw\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(3)
    public void loginWrongExistingUser() throws Exception  {
        String credentials = "{\"email\": \"aaa@acme.local\", \"password\":\"wrongPsw\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(4)
    public void loginWrongNonExistingUser() throws Exception  {
        String credentials = "{\"email\": \"bbb@acme.local\", \"password\":\"randompw\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(5)
    public void loginBadRequest() throws Exception  {
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(6)
    public void loginBadCredentialsFormat() throws Exception  {
        String credentials = "email: \"test2@acme.local\", \"password\":\"test\"";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
           
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(7)
    public void getFiles() throws Exception  {
        String jwt = loginFunc(email, "test");
        String url = "https://localhost:%d/api/v1".formatted(port)+"/files?email=" +email;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        assertNotNull(res.getBody());
    }

    @Test
    @Order(8)
    public void getFilesInvalidJWT() throws Exception  {
        String jwt = "invalidJWT";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/files?email=" +email;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(9)
    public void getFilesBadRequest() throws Exception  {
        String jwt = loginFunc(email, "test");
        String url = "https://localhost:%d/api/v1".formatted(port)+"/files?";

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(400, res.getStatusCode().value());
    }
}


