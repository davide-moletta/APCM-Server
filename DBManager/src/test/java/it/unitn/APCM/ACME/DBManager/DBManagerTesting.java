package it.unitn.APCM.ACME.DBManager;

import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.Test;
import org.junit.Test;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;

import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.Response;
import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;

@RunWith(SpringRunner.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(
        classes = DB_RESTApp.class,
        args = {""},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        useMainMethod = SpringBootTest.UseMainMethod.ALWAYS
)
public class DBManagerTesting {

    @LocalServerPort
    private int port;
    RestTemplate rest = (new SecureRestTemplateConfig("Guard_keystore.jks", "GuardC_truststore.jks")).secureRestTemplate();
    String path, email, r_groups, rw_groups, user_groups, path_hash, file_hash, url = "";

    @Test
    @Order(1)
    public void testCreateFirstFile() throws Exception  {
        path = "test17.txt";
        email = "user@amce.local";
        r_groups = "hr,students";
        rw_groups = "hr";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/newFile?" +
            "path_hash=" + path_hash +
            "&path=" + path +
            "&email=" + email +
            "&r_groups=" + r_groups +
			"&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(201, res.getStatusCode().value());
    }

    @Test
    @Order(2)
    public void testCreateSecondFile() throws Exception  {
        path = "test18.txt";
        email = "user@amce.local";
        r_groups = "hr,students";
        rw_groups = "hr";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/newFile?" +
            "path_hash=" + path_hash +
            "&path=" + path +
            "&email=" + email +
            "&r_groups=" + r_groups +
			"&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(201, res.getStatusCode().value());
    }

    @Test
    @Order(3)
    public void testCreateFileAlreadyExisting() throws Exception  {
        path = "test17.txt";
        email = "user@amce.local";
        r_groups = "hr,students";
        rw_groups = "hr";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/newFile?" +
                "path_hash=" + path_hash +
            "&path=" + path +
            "&email=" + email +
            "&r_groups=" + r_groups +
			"&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;
        
        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
    
        Assertions.assertEquals(409, res.getStatusCode().value());
    }

    @Test
    @Order(4)
    public void testCreateFileBadRequest() throws Exception  {
        url = "https://localhost:%d/api/v1".formatted(port)+"/newFile?";

        ResponseEntity<String> res = null;

        try{ 
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
    @Order(5)
    public void testGetDecryptionKeyAdmin() throws Exception  {
        path = "test17.txt";
        file_hash = "";
        email = "teacher@amce.local";
        user_groups = "teacher";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 1;

        ResponseEntity<Response> res = null;
        
        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(200, res.getStatusCode().value());
        //Check if he can read
        Assertions.assertEquals(true, res.getBody().get_auth());
        //Check if he can write
        Assertions.assertEquals(true, res.getBody().get_w_mode());
    }

    @Test
    @Order(6)
    public void testGetDecryptionKeyOwner() throws Exception  {
        path = "test17.txt";
        file_hash = "";
        email = "user@amce.local";
        user_groups = "user";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 0;

        ResponseEntity<Response> res = null;
        
        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }
            
        Assertions.assertEquals(200, res.getStatusCode().value());
        //Check if he can read
        Assertions.assertEquals(true, res.getBody().get_auth());
        //Check if he can write
        Assertions.assertEquals(true, res.getBody().get_w_mode());
    }

    @Test
	@Order(7)
    public void testGetDecryptionKeyAuthorizedWriteUser() throws Exception  {
        path = "test17.txt";
        file_hash = "";
        email = "student@amce.local";
        user_groups = "hr";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 0;

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(200, res.getStatusCode().value());
        //Check if he can read
        Assertions.assertEquals(true, res.getBody().get_auth());
        //Check if he can write
        Assertions.assertEquals(true, res.getBody().get_w_mode());
    }

    @Test
	@Order(8)
    public void testGetDecryptionKeyAuthorizedReadUser() throws Exception  {
        path = "test17.txt";
        file_hash = "";
        email = "student@amce.local";
        user_groups = "students";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 0;

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(200, res.getStatusCode().value());
        //Check if he can read
        Assertions.assertEquals(true, res.getBody().get_auth());
        //Check if he cannot write
        Assertions.assertEquals(false, res.getBody().get_w_mode());
    }

    @Test
	@Order(9)
    public void testGetDecryptionKeyUnauthorizedUser() throws Exception  {
        path = "test17.txt";
        file_hash = "";
        email = "teacher@amce.local";
        user_groups = "teacher";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 0;

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(401, res.getStatusCode().value());
    }

    @Test
	@Order(10)
    public void testGetDecryptionKeyCorruptedFile() throws Exception  {
        path = "test17.txt";
        file_hash = "WrongHash";
        email = "teacher@amce.local";
        user_groups = "teacher";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 1;

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(409, res.getStatusCode().value());
    }

    @Test
	@Order(11)
    public void testGetDecryptionKeyWrongPathHash() throws Exception  {
        path = "NotExistingPath.txt";
        file_hash = "";
        email = "teacher@amce.local";
        user_groups = "teacher";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash +
            "&email=" + email +
            "&user_groups=" + user_groups +
			"&admin=" + 1;

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
	@Order(12)
    public void testGetDecryptionKeyBadRequest() throws Exception  {
        url = "https://localhost:%d/api/v1".formatted(port)+"/decryption_key";

        ResponseEntity<Response> res = null;

        try{
            res = rest.getForEntity(url, Response.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
	@Order(13)
    public void testSaveFile() throws Exception  {
        path = "test17.txt";
        file_hash = "newFileHash";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/saveFile?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash;

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    @Test
	@Order(14)
    public void testSaveFileWrongPathHash() throws Exception  {
        path = "ThisIsNotAnExistingPath.txt";
        file_hash = "newFileHash";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/saveFile?" +
            "path_hash=" + path_hash +
            "&file_hash=" + file_hash;

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
	@Order(15)
    public void testSaveFileBadRequest() throws Exception  {
        url = "https://localhost:%d/api/v1".formatted(port)+"/saveFile";

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(400, res.getStatusCode().value());
    }

    @Test
	@Order(16)
    public void testDeleteFile() throws Exception  {
        path = "test19.txt";
        email = "user@amce.local";
        r_groups = "hr,students";
        rw_groups = "hr";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/newFile?" +
            "path_hash=" + path_hash +
            "&path=" + path +
            "&email=" + email +
            "&r_groups=" + r_groups +
			"&rw_groups=" + rw_groups;

        ResponseEntity<String> res = null;

        try{
            res = rest.postForEntity(url, null, String.class);
        } catch (HttpClientErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        url = "https://localhost:%d/api/v1".formatted(port)+"/deleteFile?" +
            "path_hash=" + path_hash;

        res = null;

        try{
            res = rest.exchange(url, HttpMethod.DELETE, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(200, res.getStatusCode().value());
    }

    @Test
	@Order(17)
    public void testDeleteNotExistingFile() throws Exception  {
        path = "test18.txt";
        path_hash = (new CryptographyPrimitive()).getHash(path.getBytes());
        url = "https://localhost:%d/api/v1".formatted(port)+"/deleteFile?" +
            "path_hash=" + path_hash;

        ResponseEntity<String> res = null;


        try{
            res = rest.exchange(url, HttpMethod.DELETE, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(500, res.getStatusCode().value());
    }

    @Test
	@Order(18)
    public void testDeleteFileBadRequest() throws Exception  {
        url = "https://localhost:%d/api/v1".formatted(port)+"/deleteFile";

        ResponseEntity<String> res = null;

        try{
            res = rest.exchange(url, HttpMethod.DELETE, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e){
            res = new ResponseEntity<>(e.getStatusCode());
        }

        Assertions.assertEquals(400, res.getStatusCode().value());
    }
}


