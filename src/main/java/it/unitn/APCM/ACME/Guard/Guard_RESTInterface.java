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

import it.unitn.APCM.ACME.DBManager.DB_RESTApp;
import it.unitn.APCM.ACME.ServerCommon.ClientResponse;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;

import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	private static final String dbServer_url = "http://localhost:8091/api/v1/decryption_key?";
	private static final String dbServer_url2 = "http://localhost:8091/api/v1/";
	private static final String filePath = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\Files";
	private static final String fP = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\";
	// encryption algorithm
	// CHECK TYPE OF ENCRYPTION ALGORITHM
	static final String algorithm = "AES";
	
	Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 15 * 1024, 2);

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
	 * Endpoint to create a new user
	 */
	@GetMapping("/newUser")
	public void createUser(@RequestParam String email, @RequestParam String password,
			@RequestParam String groups, @RequestParam int admin) {

		log.trace("got a requst to create a new user");
			
		// generate hash with argon2
		String encoded_password = encoder.encode(password);
		System.out.println("generated pass: " + encoded_password);

		// format groups
		groups = groups.replace(",", "\",\"");
		groups = "[\"" + groups + "\"]";
		System.out.println(groups);

		String insertQuery = "INSERT INTO Users(email, pass, groups, admin) VALUES (?,?,?,?)";
		try {
			PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
			prepStatement.setString(1, email);
			prepStatement.setString(2, encoded_password);
			prepStatement.setString(3, groups);
			prepStatement.setInt(4, admin);

			prepStatement.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Endpoint to login
	 */
	@GetMapping("/login")
	public ResponseEntity<String> login(@RequestParam String email, @RequestParam String password) {

		log.trace("got a requst for login from: " + email);

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

		String response = "not authenticated";
		if (validPassword) {
			response = "authenticated";
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(response, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to retrieve a file
	 */
	@GetMapping(value = "/file")
	public ResponseEntity<ClientResponse> get_file(@RequestParam String email,
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
		String path_hash = getPathHash(path);

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
		ClientResponse clientResponse = new ClientResponse();
		response.set_path_hash(path);
		response.set_auth(false);
		response.set_email(email);
		response.set_id(1);
		response.set_w_mode(false);
		response.set_key(null);

		clientResponse.set_id(1);
		clientResponse.set_path_hash(path);
		clientResponse.set_w_mode(false);
		clientResponse.set_text("");

		String fileContent = "";

		try {

			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_auth()) {
					response.set_auth(true);
					if (res.get_w_mode()) {
						// può scrivere
						response.set_w_mode(true);
						clientResponse.set_w_mode(true);
					}

					// decript del file con chiave
					InputStream in = getClass().getResourceAsStream(path);
					try {
						fileContent = IOUtils.toString(in, StandardCharsets.UTF_8);
						byte[] keyBytes = (res.get_key()).getBytes();
						System.out.println("OPEN prima: " + fileContent);
						SecretKey decK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						byte[] textDec = (new CryptographyPrimitive()).decrypt(fileContent.getBytes(), decK);
						String t = new String(textDec);
						System.out.println("OPEN: " + t);
						clientResponse.set_text(new String(textDec));
						in.close();
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
		ResponseEntity<ClientResponse> entity = new ResponseEntity<>(clientResponse, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to save a file
	 */
	@PostMapping(value = "/file")
	public ResponseEntity<String> save_file(@RequestParam String email,
			@RequestParam String password,
			@RequestParam String path,
			@RequestBody String newTextToSave) throws IOException {

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
		String path_hash = getPathHash(path);

		// creaft the request to the db interface
		String DB_request_url = dbServer_url +
				"path_hash=" + path_hash +
				"&email=" + email +
				"&user_groups=" + groupsToString +
				"&admin=" + admin +
				"&id=1";

		log.trace("Requesting for: " + DB_request_url);

		String responseString = "Impossible to save the file";

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();

		try {
			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_auth()) {
					if (res.get_w_mode()) {
						byte[] keyBytes = (res.get_key()).getBytes();
						SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						System.out.println("SAVE prima: " + newTextToSave);
						byte[] textEnc = (new CryptographyPrimitive()).encrypt(newTextToSave.getBytes(), encK);
						String t = new String(textEnc);
						System.out.println("SAVE: " + t);
						// Encrypt the file
						FileOutputStream fOut = new FileOutputStream(fP + path);
						IOUtils.write(new String(textEnc), fOut, StandardCharsets.UTF_8);
						// fOut.flush();
						fOut.close();
						responseString = "File saved";
					}
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(responseString, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint to create a new file
	 */
	@PostMapping(value = "/newFile")
	public ResponseEntity<String> new_file(@RequestParam String email,
			@RequestParam String password,
			@RequestParam String path,
			@RequestBody String text) throws IOException {
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
		String path_hash = getPathHash(path);

		// creaft the request to the db interface
		String DB_request_url = dbServer_url2 + "/newFile?" +
				"path_hash=" + path_hash +
				"&path=" + path +
				"&email=" + email +
				"&user_groups=" + groupsToString +
				"&admin=" + admin +
				"&id=1";

		log.trace("Requesting for: " + DB_request_url);

		// sends the request and capture the response
		RestTemplate restTemplate = new RestTemplate();

		try {
			// get the response and decide accordingly
			Response res = restTemplate.getForEntity(DB_request_url, Response.class).getBody();

			if (res != null) {
				if (res.get_auth()) {
					if (res.get_w_mode()) {
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
						byte[] keyBytes = (res.get_key()).getBytes();
						SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						System.out.println("CREA prima: " + text);
						byte[] textEnc = (new CryptographyPrimitive()).encrypt(text.getBytes(), encK);
						String t = new String(textEnc);
						System.out.println("CREA: " + t);
						// Encrypt the file
						FileOutputStream fOut = new FileOutputStream(fP + path);
						IOUtils.write(new String(textEnc), fOut, StandardCharsets.UTF_8);
						// fOut.flush();
						fOut.close();
					}
				}
			}
		} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
			log.error("Error in the response from DB server");
		}

		HttpHeaders headers = new HttpHeaders();

		ResponseEntity<String> entity = new ResponseEntity<>("ok", headers, HttpStatus.CREATED);

		return entity;
	}

	private String getPathHash(String path) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			byte[] bytes = md.digest(path.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			return "";
			// throw new RuntimeException(e);
		}
	}
}