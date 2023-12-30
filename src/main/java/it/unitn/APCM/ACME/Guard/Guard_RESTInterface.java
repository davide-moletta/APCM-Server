package it.unitn.APCM.ACME.Guard;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private String dbServer_url = "http://localhost:8091/decryption_key?";

	/**
	 * Endpoint to add or remove users from db
	 */
	@GetMapping("/user")
	public String add_user(@RequestParam String email, @RequestParam String pwd, @RequestParam String user_groups, @RequestParam String admin){

		return "";
	}


	/**
	 * Endpoint to "login" and retrieve a file
	 */
	@GetMapping("/file")
	public String get_file(@RequestParam String email, @RequestParam String pwd, @RequestParam String path) {

		String groups = "";
		int admin = 0;

		String userQuery = "SELECT groups, admin FROM Users WHERE email=? AND password=?";
		PreparedStatement preparedStatement;

		try {
			preparedStatement = conn.prepareStatement(userQuery);
			preparedStatement.setString(0, email);
			preparedStatement.setString(1, pwd);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				groups = rs.getString("groups");
				admin = rs.getInt("admin");
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		String path_hash = null;
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			byte[] bytes = md.digest(path.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder();
			for(int i = 0; i < bytes.length; i++){
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			path_hash = sb.toString();
		}catch (NoSuchAlgorithmException e){
			throw new RuntimeException(e);
		}

		String DB_request_url = dbServer_url + "path_hash=" + path_hash + "&user=" + email + "&user_groups=" + groups + "&admin=" + admin;

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> response = restTemplate.getForEntity(DB_request_url, String.class);

		if (response.getStatusCode() == HttpStatus.OK) {
			String responseBody = response.getBody();
			return responseBody;
		} else {
			return "file does not exists";
		}
	}
}
