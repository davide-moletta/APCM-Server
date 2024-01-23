package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.unitn.APCM.ACME.ServerCommon.ClientResponse;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;
import it.unitn.APCM.ACME.ServerCommon.UserPrivilege;

import java.net.URI;
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

	// private static final String fP =
	// (((newFile(System.getProperty("java.io.tmpdir"),
	// "ACMEFILES")).toURI()).toString()).substring(6);
	private static final String fP = URI.create("Guard/src/main/java/it/unitn/APCM/ACME/Guard/Files/").toString();

	// encryption algorithm
	static final String algorithm = "AES";
	Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 15 * 1024, 2);

	@Autowired
	private RestTemplate secureRestTemplate;

	@Autowired
	private JWT_Utils JWT_Utils;

	private String fetch_files(URI path, String files) {
		File directoryPath = new File(path.getPath());
		String[] contents = directoryPath.list();

		if (contents != null) {
			for (String content : contents) {
				if (content.contains(".")) {
					// is a file
					files = files.concat(path + content + ",");
				} else {
					// is a directory
					files = files.concat(fetch_files(URI.create(path + content + "/"), ""));
				}
			}
		}
		return files.replace(fP, "");
	}

	/**
	 * Endpoint to retrieve the available files
	 */
	@GetMapping("/files")
	public ResponseEntity<String> get_files(@RequestParam String email, @RequestHeader String jwt) {

		log.trace("got a request for available files from: " + email);

		String files = "";

		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.UNAUTHORIZED;

		if (JWT_Utils.validateToken(jwt, email)) {
			files = fetch_files(URI.create(fP), "");
			status = HttpStatus.OK;
		}

		return new ResponseEntity<>(files, headers, status);
	}

	/**
	 * Endpoint to create a new user
	 */
	// @GetMapping("/newUser")
	// public ResponseEntity createUser(@RequestParam String email, @RequestParam String password,
	// 		@RequestParam String groups, @RequestParam int admin) {

	// 	log.trace("got a requst to create a new user");

	// 	// generate hash with argon2
	// 	String encoded_password = encoder.encode(password);
	// 	// System.out.println("generated pass: " + encoded_password);

	// 	// format groups
	// 	groups = groups.replace(",", "\",\"");
	// 	groups = "[\"" + groups + "\"]";
	// 	// System.out.println(groups);

	// 	String response = "error";
	// 	HttpStatus status = HttpStatus.BAD_REQUEST;

	// 	String insertQuery = "INSERT INTO Users(email, pass, groups, admin) VALUES (?,?,?,?)";
	// 	try {
	// 		PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
	// 		prepStatement.setString(1, email);
	// 		prepStatement.setString(2, encoded_password);
	// 		prepStatement.setString(3, groups);
	// 		prepStatement.setInt(4, admin);

	// 		prepStatement.executeUpdate();

	// 		response = "success";
	// 		status = HttpStatus.OK;
	// 	} catch (SQLException e) {
	// 		log.error("User already existent");
	// 	}

	// 	return new ResponseEntity<>(response, new HttpHeaders(), status);
	// }

	/**
	 * Endpoint to login
	 */
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody String credentials) {
		String email = null, password = null;
		ObjectMapper objectMapper = new ObjectMapper();

		log.trace("got a login request from: " + email);

		try {
			JsonNode jsonNode = objectMapper.readTree(credentials);

			email = jsonNode.get("email").asText();
			password = jsonNode.get("password").asText();
		} catch (Exception e) {
			e.printStackTrace(); // Handle the exception appropriately
		}

		String loginQuery = "SELECT pass FROM Users WHERE email=?";
		PreparedStatement preparedStatement;

		String stored_password = null;

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

		boolean validPassword = false;
		if (stored_password != null) {
			// check if the password is valid with argon2
			validPassword = encoder.matches(password, stored_password);
		}

		HttpHeaders headers = new HttpHeaders();

		String response = "error";
		HttpStatus status = HttpStatus.UNAUTHORIZED;
		if (validPassword) {
			response = "success";
			status = HttpStatus.OK;

			UserPrivilege userPrivilege = getUserPrivilege(email);

			User user = new User(email, userPrivilege.getGroups(),
					userPrivilege.getAdmin());

			final String jwt = JWT_Utils.generateToken(user);

			headers.add("jwt", jwt);
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to retrieve a file
	 */
	@GetMapping(value = "/file")
	public ResponseEntity<ClientResponse> get_file(@RequestParam String email,
			@RequestParam String path, @RequestHeader String jwt) throws IOException {

		log.trace("got a request for file: " + path + " from: " + email);

		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.UNAUTHORIZED;

		ClientResponse clientResponse = new ClientResponse(path, false, false, "");

		if (JWT_Utils.validateToken(jwt, email)) {

			UserPrivilege user = new UserPrivilege(JWT_Utils.extractAdmin(jwt), JWT_Utils.extractGroups(jwt));

			String completePath = URI.create(fP + path).toString();

			InputStream inputStream = new FileInputStream(completePath);
			// set up buffer
			long fileSize = new File(completePath).length();
			byte[] allBytes = null;
			if ((int) fileSize != 0) {
				allBytes = new byte[(int) fileSize];
				// read from file and return result
				inputStream.read(allBytes);
				inputStream.close();
			}

			String file_hash = "";

			if ((int) fileSize != 0) {
				file_hash = (new CryptographyPrimitive()).getHash(allBytes);
			}

			// craft the request to the db interface
			String DB_request_url = dbServer_url + "decryption_key?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&file_hash=" + file_hash +
					"&open=true" +
					"&email=" + email +
					"&user_groups=" + user.getGroups() +
					"&admin=" + user.getAdmin();

			log.trace("Requesting for: " + DB_request_url);

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;
			status = HttpStatus.OK;

			try {

				// get the response and decide accordingly
				Response res = srt.getForEntity(DB_request_url, Response.class).getBody();

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
						} else {
							clientResponse.set_text("");
						}
					}
				}
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				status = HttpStatus.INTERNAL_SERVER_ERROR;
				clientResponse = null;
				log.error("Error in the response from DB server");
			}
		}

		return new ResponseEntity<>(clientResponse, headers, status);
	}

	/**
	 * Endpoint to save a file
	 */
	@PostMapping(value = "/file")
	public ResponseEntity<String> save_file(@RequestParam String email,
			@RequestParam String path,
			@RequestBody String newTextToSave, @RequestHeader String jwt) throws IOException {

		log.trace("got a request to save new content for file: " + path + " from: " + email);

		String response = "error";
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.UNAUTHORIZED;

		if (JWT_Utils.validateToken(jwt, email)) {

			UserPrivilege user = new UserPrivilege(JWT_Utils.extractAdmin(jwt), JWT_Utils.extractGroups(jwt));

			// creaft the request to the db interface
			String DB_request_url = dbServer_url + "decryption_key?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&file_hash=" +
					"&open=false" +
					"&email=" + email +
					"&user_groups=" + user.getGroups() +
					"&admin=" + user.getAdmin();

			log.trace("Requesting for: " + DB_request_url);

			status = HttpStatus.INTERNAL_SERVER_ERROR;

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;

			try {
				// get the response and decide accordingly
				Response res = srt.getForEntity(DB_request_url, Response.class).getBody();

				if (res != null) {
					if (res.get_w_mode() && !newTextToSave.isEmpty()) {
						byte[] keyBytes = res.get_key();
						SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						byte[] textEnc = (new CryptographyPrimitive()).encrypt(newTextToSave.getBytes(), encK);

						// Save encrypted file to file
						String completePath = URI.create(fP + path).toString();
						OutputStream outputStream = new FileOutputStream(completePath);
						outputStream.write(textEnc, 0, textEnc.length);
						outputStream.flush();
						outputStream.close();

						String DB_request2_url = dbServer_url + "saveFile?" +
								"path_hash="
								+ (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8))
								+
								"&file_hash=" + (new CryptographyPrimitive()).getHash(textEnc);

						String res2 = srt.postForEntity(DB_request2_url, null, String.class).getBody();
						assert res2 != null;
						if (res2.equals("success")) {
							status = HttpStatus.CREATED;
							response = "success";
						}
					}
				}
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				log.error("Error in the response from DB server");
			}
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to create a new file
	 */
	@GetMapping(value = "/newFile")
	public ResponseEntity<String> new_file(@RequestParam String email,
			@RequestParam String path,
			@RequestParam String r_groups,
			@RequestParam String rw_groups,
			@RequestHeader String jwt) throws Exception {

		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String response = "error";

		log.trace("got a request to create a new file from: " + email);

		if (JWT_Utils.validateToken(jwt, email)) {
			// craft the request to the db interface
			String DB_request_url = dbServer_url + "newFile?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&path=" + path +
					"&email=" + email +
					"&r_groups=" + r_groups +
					"&rw_groups=" + rw_groups;

			log.trace("Requesting for: " + DB_request_url);

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;

			try {
				// get the response and decide accordingly
				ResponseEntity<String> ent = srt.getForEntity(DB_request_url, String.class);
				String res = ent.getBody();

				if (res != null && res.equals("success")) {
					String[] splittedPath = path.split("/");
					int indexName = splittedPath.length - 1;
					String dirPath = "";
					for (int i = 0; i < indexName; i++) {
						dirPath += "/" + splittedPath[i];
					}
					String realpath = URI.create(fP + dirPath).getPath();
					File dir = new File(realpath);
					dir.mkdirs();
					File f = new File(realpath, splittedPath[indexName]);
					f.createNewFile();

					response = "success";
					status = HttpStatus.CREATED;
				}
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				log.error("Error in the response from DB server");
			}
		}

		return new ResponseEntity<>(response, headers, status);
	}

	private UserPrivilege getUserPrivilege(String email) {
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