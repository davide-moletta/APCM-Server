package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;

import it.unitn.APCM.ACME.ServerCommon.ClientResponse;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;
import it.unitn.APCM.ACME.ServerCommon.UserPrivilege;

import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	private static final String dbServer_url = String.format("https://%s/api/v1/", Guard_RESTApp.srvdb);
	private static final String fP = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\";
	// encryption algorithm
	static final String algorithm = "AES";

	Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 15 * 1024, 2);

	private String fetch_files(String path, String files) {

		File directoryPath = new File(path);
		String contents[] = directoryPath.list();

		for (String content : contents) {
			if (content.contains(".")) {
				// is a file
				files = files.concat(path + "/" + content + ",");
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

		log.trace("got a request for available files");
		String files = fetch_files(fP + "Files", "");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(files, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to create a new user
	 */
	@GetMapping("/newUser")
	public void createUser(@RequestParam String email, @RequestParam String password,
			@RequestParam String groups, @RequestParam int admin) {

		log.trace("got a requst to create a new user");

		// generate hash with argon2
		String encoded_password = encoder.encode(password);
		// System.out.println("generated pass: " + encoded_password);

		// format groups
		groups = groups.replace(",", "\",\"");
		groups = "[\"" + groups + "\"]";
		// System.out.println(groups);

		String insertQuery = "INSERT INTO Users(email, pass, groups, admin) VALUES (?,?,?,?)";
		try {
			PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
			prepStatement.setString(1, email);
			prepStatement.setString(2, encoded_password);
			prepStatement.setString(3, groups);
			prepStatement.setInt(4, admin);

			prepStatement.executeUpdate();
		} catch (SQLException e) {
			log.error("User already existent");
		}
	}

	/**
	 * Endpoint to login
	 */
	@GetMapping("/login")
	public ResponseEntity<String> login(@RequestParam String email, @RequestParam String password) {

		log.trace("got a login request from: " + email);

		String loginQuery = "SELECT pass FROM Users WHERE email=?";
		PreparedStatement preparedStatement;

		String stored_password = "";

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(loginQuery);
			preparedStatement.setString(1, email);
			ResultSet rs = preparedStatement.executeQuery();

			if (rs.next())
				stored_password = rs.getString("pass");
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		// check if the password is valid with argon2
		boolean validPassword = encoder.matches(password, stored_password);

		String response = "error";
		HttpStatus status = HttpStatus.UNAUTHORIZED;
		if (validPassword) {
			response = "success";
			status = HttpStatus.OK;
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(response, headers, status);

		return entity;
	}

	/**
	 * Endpoint to retrieve a file
	 */
	@GetMapping(value = "/file")
	public ResponseEntity<ClientResponse> get_file(@RequestParam String email,
			@RequestParam String path) throws IOException {

		UserPrivilege user = getUserPrivilege(email);

		InputStream inputStream = new FileInputStream(fP + path);
		// set up buffer
		long fileSize = new File(fP + path).length();
		byte[] allBytes = null;
		if ((int) fileSize != 0) {
			allBytes = new byte[(int) fileSize];
			// read from file and return result
			inputStream.read(allBytes);
			inputStream.close();	
		}

		String file_hash = "";

		if((int) fileSize != 0){
			file_hash = (new CryptographyPrimitive()).getHash(allBytes);
		}

		// creaft the request to the db interface
		String DB_request_url = dbServer_url + "decryption_key?" +
				"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
				"&file_hash=" + file_hash  +
				"&open=true" + 
				"&email=" + email +
				"&user_groups=" + user.getGroups() +
				"&admin=" + user.getAdmin();

		log.trace("Requesting for: " + DB_request_url);

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();
		HttpStatus status = HttpStatus.OK;
		ClientResponse clientResponse = new ClientResponse(path, false, false, "");

		try {

			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_auth()) {
					clientResponse.set_auth(true);
					if (res.get_w_mode()) {
						clientResponse.set_w_mode(true);
					}

					if ((int) fileSize != 0) {
						byte[] keyBytes = res.get_key();
						SecretKey decK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						byte[] textDec = (new CryptographyPrimitive()).decrypt(allBytes, decK);
						clientResponse.set_text(new String(textDec));
					}else{
						clientResponse.set_text("");
					}
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			status = HttpStatus.INTERNAL_SERVER_ERROR;
			clientResponse = null;
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<ClientResponse> entity = new ResponseEntity<>(clientResponse, headers, status);

		return entity;
	}

	/**
	 * Endpoint to save a file
	 */
	@PostMapping(value = "/file")
	public ResponseEntity<String> save_file(@RequestParam String email,
			@RequestParam String path,
			@RequestBody String newTextToSave) throws IOException {

		UserPrivilege user = getUserPrivilege(email);

		// creaft the request to the db interface
		String DB_request_url = dbServer_url + "decryption_key?" +
				"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
				"&file_hash=" +
				"&open=false" + 
				"&email=" + email +
				"&user_groups=" + user.getGroups() +
				"&admin=" + user.getAdmin();

		log.trace("Requesting for: " + DB_request_url);

		String responseString = "error";
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();

		try {
			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_w_mode() && !newTextToSave.isEmpty()) {
					byte[] keyBytes = res.get_key();
					SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
					byte[] textEnc = (new CryptographyPrimitive()).encrypt(newTextToSave.getBytes(), encK);

					// Save encrypted file to file
					OutputStream outputStream = new FileOutputStream(fP + path);
					outputStream.write(textEnc, 0, textEnc.length);
					outputStream.flush();
					outputStream.close();

					String DB_request2_url = dbServer_url + "saveFile?" +
						"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
						"&file_hash=" + (new CryptographyPrimitive()).getHash(textEnc);

					String res2 = restTemplate.postForEntity(DB_request2_url, null, String.class).getBody();
					if(res2.equals("success")){
						status = HttpStatus.CREATED;
						responseString = "success";
					}
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(responseString, headers, status);

		return entity;
	}

	/**
	 * Endpoint to create a new file
	 */
	@GetMapping(value = "/newFile")
	public ResponseEntity<String> new_file(@RequestParam String email,
			@RequestParam String path,
			@RequestParam String r_groups,
			@RequestParam String rw_groups) throws IOException {

		String response = "error";
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		// creaft the request to the db interface
		String DB_request_url = dbServer_url + "/newFile?" +
				"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
				"&path=" + path +
				"&email=" + email +
				"&r_groups=" + r_groups +
				"&rw_groups=" + rw_groups;

		log.trace("Requesting for: " + DB_request_url);

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();

		try {
			// get the response and decide accordingly
			String res = restTemplate.getForEntity(DB_request_url, String.class).getBody();

			if (res != null && res.equals("success")) {
				String[] splittedPath = path.split("/");
				int indexName = splittedPath.length - 1;
				String dirPath = "";
				for (int i = 0; i < indexName; i++) {
					dirPath += "/" + splittedPath[i];
				}
				File dir = new File(fP + dirPath);
				dir.mkdirs();
				File f = new File(fP + dirPath, splittedPath[indexName]);
				f.createNewFile();

				response = "success";
				status = HttpStatus.CREATED;
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();

		ResponseEntity<String> entity = new ResponseEntity<>(response, headers, status);

		return entity;
	}

	private UserPrivilege getUserPrivilege(String email){
		ArrayList<String> groups = null;
		int admin = -1;
		String userQuery = "SELECT groups, admin FROM Users WHERE email=?";
		PreparedStatement preparedStatement;

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(userQuery);
			preparedStatement.setString(1, email);
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
			for (String group : groups) {
				groupsToString = groupsToString.concat(group + ",");
			}
			groupsToString = groupsToString.substring(0, groupsToString.length() - 1);
		}

		return new UserPrivilege(admin, groupsToString);
	}
}