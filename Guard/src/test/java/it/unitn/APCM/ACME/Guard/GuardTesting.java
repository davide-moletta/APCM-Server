package it.unitn.APCM.ACME.Guard;

import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.Test;
import org.junit.Test;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;

import java.util.List;




/**
 * Testing Class for Guard component
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = Guard_RESTApp.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// @ActiveProfiles("test") // for application-test.properties
public class GuardTesting {

    @LocalServerPort
    private int port;
    RestTemplate rest = (new SecureRestTemplateConfig("Client_keystore.jks", "Client_truststore.jks")).secureRestTemplate();

    @Test
    public void login() throws Exception  {
        String credentials = "{\"email\": \"test2@acme.local\", \"password\":\"test\"}";
        String url = "https://localhost:%d/api/v1".formatted(port)+"/login";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        List<String> jwtlist = res.getHeaders().get("jwt");
        String jwt = null;
        if (jwtlist != null) {
           jwt = jwtlist.get(0);
        }
        assertNotNull(jwt);
        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    @Test
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
}


