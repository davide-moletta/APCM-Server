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

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URI;
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
    String psw_prof1 = System.getenv("PSW_PROFESSOR1");
    String psw_prof2 = System.getenv("PSW_PROFESSOR2");
    String psw_stud1 = System.getenv("PSW_STUDENT1");
    String psw_admin = System.getenv("PSW_ADMIN");
    String psw_guest = System.getenv("PSW_GUEST");
    String newTestingPath = "disi_shared/testingExample.txt";
     
    @Test
    @Order(1)
    public void login() throws Exception  {
        loginFunc(email, psw_prof1);      
    }
    
    @Test
    @Order(2)
    public void loginWrongPsw() throws Exception  {
        String credentials = "{\"email\": \""+ email + "\", \"password\":\"wrongPsw\"}";
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
        String credentials = "{\"email\": \"pippo@acme.local\", \"password\":\""+ psw_prof1 +"\"}";
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
        String jwt = loginFunc(email, psw_prof1);
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
        String jwt = loginFunc(email, psw_prof1);
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
    public void newFile() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String r_groups = "disi_shared,professors";
        String rw_groups = "disi_shared";
        String url = fixedUrl + "newFile?email=" + email + 
            "&path=" + newTestingPath +
            "&r_groups=" + r_groups +
            "&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(201, res.getStatusCode().value());
    }

    @Test
    @Order(11)
    public void newFileAlreadyExisting() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String r_groups = "disi_shared";
        String rw_groups = "";
        String url = fixedUrl + "newFile?email=" + email + 
            "&path=" + newTestingPath +
            "&r_groups=" + r_groups +
            "&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(12)
    public void newFilePathTraversal() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String r_groups = "disi_shared";
        String rw_groups = "";
        String path = "../../../disi_shared/prof1_shared2.txt";
        String url = fixedUrl + "newFile?email=" + email + 
            "&path=" + path +
            "&r_groups=" + r_groups +
            "&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(13)
    public void newFileInvalidJWT() throws Exception  {
        String jwt = "wrongJWT";
        String r_groups = "disi_shared";
        String rw_groups = "";
        String url = fixedUrl + "newFile?email=" + email + 
            "&path=" + newTestingPath +
            "&r_groups=" + r_groups +
            "&rw_groups=" + rw_groups;

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
    @Order(14)
    public void newFileBadRequest() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String url = fixedUrl + "newFile?";

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
    @Order(15)
    public void saveFileOwner() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String text = "First text to save";
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(201, res.getStatusCode().value());
    }

    @Test
    @Order(16)
    public void saveFileAdmin() throws Exception  {
        String ownEmail = "admin@acme.local";
        String jwt = loginFunc(ownEmail,psw_admin);
        String text = "admin Text";
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(201, res.getStatusCode().value());

        url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res2 = null;
        
        try{
            res2 = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res2 = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res2.getStatusCode().value());
        Assertions.assertEquals(true, res2.getBody().get_w_mode());
        Assertions.assertEquals(true, res2.getBody().get_auth());
        assertNotNull(res2.getBody().get_text());
        Assertions.assertEquals("admin Text", res2.getBody().get_text());
    }

    @Test
    @Order(17)
    public void saveFileAuthorizedWriterUser() throws Exception  {
        String ownEmail = "student1@acme.local";
        String jwt = loginFunc(ownEmail,psw_stud1);
        String text = "New text to save";
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(201, res.getStatusCode().value());
    }

    @Test
    @Order(18)
    public void saveFileUnauthorizedWriterUser() throws Exception  {
        String ownEmail = "professor2@acme.local";
        String jwt = loginFunc(ownEmail, psw_prof2);
        String text = "New text to save";
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(403, res.getStatusCode().value());
    }

    @Test
    @Order(19)
    public void saveFileUnexistingFile() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String path = "disi_shared/pippo.txt";
        String text = "New text to save";
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + path;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(20)
    public void saveFilePathTraversal() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String path = "disi_shared/../../../pippo.txt";
        String text = "New text to save";
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + path;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(21)
    public void saveFileInvalidJWT() throws Exception  {
        String jwt = "wrongJWT";
        String text = "New text to save";
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(22)
    public void saveFileBadRequest() throws Exception  {
        String jwt = loginFunc(email, psw_prof1);
        String text = "New text to save";
        String url = fixedUrl + "file?";

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.POST, new HttpEntity<String>(text, headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(23)
    public void getFileOwner() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String url = fixedUrl + "file?email=" + email + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        Assertions.assertEquals(true, res.getBody().get_w_mode());
        Assertions.assertEquals(true, res.getBody().get_auth());
        assertNotNull(res.getBody().get_text());
        Assertions.assertEquals("New text to save", res.getBody().get_text());
    }

    @Test
    @Order(24)
    public void getFileAdmin() throws Exception  {
        String ownEmail = "admin@acme.local";
        String jwt = loginFunc(ownEmail,psw_admin);
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        Assertions.assertEquals(true, res.getBody().get_w_mode());
        Assertions.assertEquals(true, res.getBody().get_auth());
        assertNotNull(res.getBody().get_text());
        Assertions.assertEquals("New text to save", res.getBody().get_text());
    }

    
    @Test
    @Order(25)
    public void getFileAuthorizedWriterUser() throws Exception  {
        String ownEmail = "student1@acme.local";
        String jwt = loginFunc(ownEmail,psw_stud1);
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        Assertions.assertEquals(true, res.getBody().get_w_mode());
        Assertions.assertEquals(true, res.getBody().get_auth());
        assertNotNull(res.getBody().get_text());
        Assertions.assertEquals("New text to save", res.getBody().get_text());
    }

    @Test
    @Order(26)
    public void getFileAuthorizedReadUser() throws Exception  {
        String ownEmail = "professor2@acme.local";
        String jwt = loginFunc(ownEmail,psw_prof2);
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
        Assertions.assertEquals(false, res.getBody().get_w_mode());
        Assertions.assertEquals(true, res.getBody().get_auth());
        assertNotNull(res.getBody().get_text());
        Assertions.assertEquals("New text to save", res.getBody().get_text());
    }

    @Test
    @Order(27)
    public void getFileUnauthorizedUser() throws Exception  {
        String ownEmail = "guest@acme.local";
        String jwt = loginFunc(ownEmail,psw_guest);
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(403, res.getStatusCode().value());
    }

    @Test
    @Order(28)
    public void getFileAuthorizedWriterUserPathTraversal() throws Exception  {
        String ownEmail = "student1@acme.local";
        String jwt = loginFunc(ownEmail,psw_stud1);
        String path = "../../disi_shared/prof1_shared2.txt";
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + path;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(29)
    public void getFileInvalidJWT() throws Exception  {
        String ownEmail = "student1@acme.local";
        String jwt = "wrongJWT";
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(30)
    public void getFileBadRequest() throws Exception  {
        
        String url = fixedUrl + "file?";

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(31)
    public void getFileCorrupted() throws Exception  {
        String completePath = URI.create("src/test/java/it/unitn/APCM/ACME/Guard/Files/" + newTestingPath).toString();
        byte[] text = "ciao".getBytes();
        //Corruption of the file
        try (OutputStream outputStream = new FileOutputStream(completePath)) {
            outputStream.write(text, 0, text.length);
            outputStream.flush();
            outputStream.close();
        }
        
        String ownEmail = "student1@acme.local";
        String jwt = loginFunc(ownEmail,psw_stud1);
        String url = fixedUrl + "file?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<ClientResponse> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), ClientResponse.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(412, res.getStatusCode().value());
    }

    @Test
    @Order(32)
    public void deleteFileUnauthorizedUser() throws Exception  {
        String ownEmail = "professor2@acme.local";
        String jwt = loginFunc(ownEmail,psw_prof2);
        String url = fixedUrl + "delete?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(403, res.getStatusCode().value());
    }

    @Test
    @Order(33)
    public void deleteFilePathTraversal() throws Exception  {
        String ownEmail = "professor2@acme.local";
        String jwt = loginFunc(ownEmail,psw_prof2);
        String path = "../../disi_shared/prof1_shared2.txt";
        String url = fixedUrl + "delete?email=" + ownEmail + 
            "&path=" + path;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
    @Order(34)
    public void deleteFileInvalidJWT() throws Exception  {
        String ownEmail = "professor2@acme.local";
        String jwt = "wrongJWT";
        String url = fixedUrl + "delete?email=" + ownEmail + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
    @Order(35)
    public void deleteFileBadRequest() throws Exception  {
        String url = fixedUrl + "delete?";

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        
        try{
            res = rest.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(36)
    public void deleteFileAuthorizedUser() throws Exception  {
        String jwt = loginFunc(email,psw_prof1);
        String url = fixedUrl + "delete?email=" + email + 
            "&path=" + newTestingPath;

        ResponseEntity<String> res = null;
        HttpHeaders headers = new HttpHeaders();
        headers.add("jwt", jwt);
        
        try{
            res = rest.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
        
        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    private String loginFunc(String email, String psw_prof1){
        String credentials = "{\"email\": \""+ email + "\", \"password\":\""+ psw_prof1 +"\"}";
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

        return jwt;
    }
}


