package it.unitn.APCM.ACME.Guard;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;

import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;
import it.unitn.APCM.ACME.Guard.Objects.ClientResponse;

import static org.junit.Assert.assertNotNull;

import java.util.List;

/**
 * Testing Class for Guard component
 */
@RunWith(SpringRunner.class)
@TestMethodOrder(OrderAnnotation.class)
@SpringBootTest
public class GuardTesting {
    String fixedUrl = "https://localhost:50881/api/v1/";
    RestTemplate rest = (new SecureRestTemplateConfig("Client_keystore.jks", "Client_truststore.jks")).secureRestTemplate();
    String email = "professor1@acme.local";
    String psw = System.getenv("PSW_PROFESSOR1");

    
    private String loginFunc(String email, String psw){
        String credentials = "{\"email\": \""+ email + "\", \"password\":\""+ psw +"\"}";
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
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
        String credentials = "{\"email\": \""+ email + "\", \"password\":\""+ psw +"\"}";
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
           
        String jwt = "";
        List<String> jwtlist = res.getHeaders().get("jwt");
        if (jwtlist != null) {
           jwt = jwtlist.get(0);
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        assertNotNull(jwt);
    }
    
    @Test
    @Order(2)
    public void loginWrongPSW() throws Exception  {
        String credentials = "{\"email\": \""+ email + "\", \"password\":\"wrongPSW\"}";
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(3)
    public void loginWrongExistingUser() throws Exception  {
        String credentials = "{\"email\": \"pippo@acme.local\", \"password\":\""+ psw +"\"}";
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(4)
    public void loginWrongNonExistingUser() throws Exception  {
        String credentials = "{\"email\": \"pippo@acme.local\", \"password\":\"wrongPsw\"}";
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(5)
    public void loginBadRequest() throws Exception  {
        String url = fixedUrl + "login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(6)
    public void loginBadCredentialsFormat() throws Exception  {
        String credentials = "email: \"pippo@acme.local\", \"password\":\"test\"";
        String url = fixedUrl + "login";

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
        String jwt = loginFunc(email, psw);
        String url = fixedUrl + "files?email=" +email;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        assertNotNull(res.getBody());
    }

    @Test
    @Order(8)
    public void getFilesInvalidJWT() throws Exception  {
        String jwt = "invalidJWT";
        String url = fixedUrl + "files?email=" +email;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(9)
    public void getFilesBadRequest() throws Exception  {
        String jwt = loginFunc(email, psw);
        String url = fixedUrl + "files?";

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(400, res.getStatusCode().value());
    }
    
    @Test
    @Order(10)
    public void getFile() throws Exception  {
        String jwt = loginFunc(email,psw);
        String path = "professors/prof1_grades.txt";
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + path;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        Assertions.assertEquals(res.getBody().get_w_mode(), true);
        Assertions.assertEquals(res.getBody().get_auth(), true);
        assertNotNull(res.getBody().get_text());
    }
}


