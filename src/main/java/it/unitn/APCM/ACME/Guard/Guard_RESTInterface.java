package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.IOUtils;
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
	private static final String dbServer_url = "http://localhost:8091/api/v1/decryption_key?";
	private static final String filePath = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\Files";

	private String fetch_files(String path, String files) {

		File directoryPath = new File(path);
		String contents[] = directoryPath.list();

		for (String content : contents) {
			if (content.contains(".")) {
				// is a file
				files = files.concat(path + "/" + content + "\n");
			} else {
				// is a directory
				files = files.concat(fetch_files(path + "/" + content, ""));
			}
		}
		return files.replace("src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\", "");
	}

	/**
	 * Endpoint to retrieve the available files
	 */
	@GetMapping("/files")
	public ResponseEntity<String> get_files() {

		log.trace("got a requst for available files");
		String files = fetch_files(filePath, "");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(files, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to login
	 */
	@GetMapping("/login")
	public ResponseEntity<String> login(@RequestParam String email, @RequestParam String password) {

		log.trace("got a requst for login from: " + email);

		String loginQuery = "SELECT email FROM Users WHERE email=? AND pass=?";
		PreparedStatement preparedStatement;

		String response = "not authenticated";

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(loginQuery);
			preparedStatement.setString(1, email);
			preparedStatement.setString(2, password);
			ResultSet rs = preparedStatement.executeQuery();

			if (rs.next())
				response = "authenticated";
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(response, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to retrieve a file
	 */
	@GetMapping(value = "/file")
	public ResponseEntity<String> get_file(@RequestParam String email,
			@RequestParam String password,
			@RequestParam String path) throws IOException {

		ArrayList<String> groups = null;
		int admin = -1;
		String userQuery = "SELECT groups, admin FROM Users WHERE email=? AND pass=?";
		PreparedStatement preparedStatement;

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(userQuery);
			preparedStatement.setString(1, email);
			preparedStatement.setString(2, password);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				groups = new JSONToArray(rs.getString("groups"));
				admin = rs.getInt("admin");
			}
		} catch (SQLException | JsonProcessingException e) {
			throw new RuntimeException(e);
		}

		// transform the array of groups into a string with separator ","
		String groupsToString = "";
		if (groups != null) {
			for (int i = 0; i < groups.size(); i++) {
				groupsToString = groupsToString.concat(groups.get(i) + ",");
			}
			groupsToString = groupsToString.substring(0, groupsToString.length() - 1);
		}

		// transform the received path into the corresponding hash with SHA-512
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

		// creaft the request to the db interface
		String DB_request_url = dbServer_url +
				"path_hash=" + path_hash +
				"&email=" + email +
				"&user_groups=" + groupsToString +
				"&admin=" + admin +
				"&id=1";

		log.trace("Requesting for: " + DB_request_url);

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();

		Response response = new Response();
		response.set_path_hash(path);
		response.set_auth(false);
		response.set_email(email);
		response.set_id(1);
		response.set_w_mode(false);
		response.set_key(null);

		String fileContent = "";

		try {

			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_auth()) {
					if (res.get_w_mode()) {
						// può fare tutto
						response.set_auth(true);
						response.set_w_mode(true);
					} else {
						// può solo leggere
						// display del file senza "salva"
						response.set_auth(true);
					}

					// decript del file con chiave

					InputStream in = getClass().getResourceAsStream(path);
					try {
						fileContent = IOUtils.toString(in, StandardCharsets.UTF_8);
					} catch (IOException e) {
						// Handle the exception according to your application's logic
						log.error("Error reading file: " + e.getMessage());
					}
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(fileContent, headers, HttpStatus.CREATED);

		return entity;
	}
}