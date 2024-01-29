package it.unitn.APCM.ACME.DBManager;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;

import it.unitn.APCM.ACME.Guard.Guard_RESTApp;
import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;


@RunWith(SpringRunner.class)
@SpringBootTest(classes=Guard_RESTApp.class)
public class GuardTesting {
    
    RestTemplate rest = (new SecureRestTemplateConfig("Client_keystore.jks", "Client_truststore.jks")).secureRestTemplate();
    String url, jwt = "";

    @Test
    public void login() throws Exception  {
        String credentials = "{\"email\": \"test2@acme.local\", \"password\":\"test\"}";
        url = "https://localhost:8090/api/v1/login?";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        jwt = res.getHeaders().get("jwt").get(0);

        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    @Test
    public void loginWrongPSW() throws Exception  {
        String credentials = "{\"email\": \"test2@acme.local\", \"password\":\"wrongPsw\"}";
        url = "https://localhost:8090/api/v1/login?";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, credentials, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    public void loginWrongUser() throws Exception  {
        String credentials = "{\"email\": \"aaa@acme.local\", \"password\":\"wrongPsw\"}";
        url = "https://localhost:8090/api/v1/login?";

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
        url = "https://localhost:8090/api/v1/login?";

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(400, res.getStatusCode().value());
    }
}


