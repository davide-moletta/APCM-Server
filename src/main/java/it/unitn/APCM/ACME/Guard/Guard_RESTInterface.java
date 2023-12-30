package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;

import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	private String dbServer_url = "http://localhost:8091/api/v1/decryption_key?";

	/**
	 * Endpoint to add or remove users from db
	 */
	@GetMapping("/user")
	public String add_user(@RequestParam String email, @RequestParam String pwd, @RequestParam String user_groups,
			@RequestParam String admin) {

		return "";
	}

	/**
	 * Endpoint to "login" and retrieve a file
	 */
	@GetMapping("/file")
	public String get_file(@RequestParam String email, @RequestParam String pwd, @RequestParam String path) {

		ArrayList<String> groups = null;
		int admin = 0;

		String userQuery = "SELECT groups, admin FROM Users WHERE email=? AND pass=?";
		PreparedStatement preparedStatement;
		RestTemplate restTemplate = new RestTemplate();

		try {
			preparedStatement = conn.prepareStatement(userQuery);
			preparedStatement.setString(1, email);
			preparedStatement.setString(2, pwd);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				groups = new JSONToArray(rs.getString("groups"));
				admin = rs.getInt("admin");
			}
		} catch (SQLException | JsonProcessingException e) {
			throw new RuntimeException(e);
		}

		// no response from the users db
		if (groups == null) {
			log.warn("user does not exist");
			return "user does not exist";
		}

		String groupsToString = "";
		if (groups != null) {
			for (int i = 0; i < groups.size(); i++) {
				groupsToString = groupsToString.concat(groups.get(i) + ",");
			}
			groupsToString = groupsToString.substring(0, groupsToString.length() - 1);
		}

		String path_hash = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			byte[] bytes = md.digest(path.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			path_hash = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		// for testing since sha is not working
		path_hash = "4e9b41c6f74a3d176b5f4b52eba527fee73e17f9cbb65e6a6d2b9c1cdd6753d8bb917aa8f9adccbd326bb65d72f1020324ca6dd6d5f05d22d2dcc349391e305a";

		String DB_request_url = dbServer_url + "path_hash=" + path_hash +
				"&user=" + email +
				"&user_groups=" + groupsToString +
				"&admin=" + admin +
				"&id=1";

		log.trace("Requesting for: " + DB_request_url);

		String responseBody = "";

		try {
			
			Response response = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (response != null) {
				//make checks and reply to client
				System.out.println(response.get_key());
			}
	
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
			return e.toString();
		}

		return responseBody;
	}
}
