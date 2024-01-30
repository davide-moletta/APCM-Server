package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONArray;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
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

import it.unitn.APCM.ACME.Guard.Objects.ClientResponse;
import it.unitn.APCM.ACME.Guard.Objects.JWT_Utils;
import it.unitn.APCM.ACME.Guard.Objects.User;
import it.unitn.APCM.ACME.Guard.Objects.UserPrivilege;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;
import it.unitn.APCM.ACME.ServerCommon.SecureRestTemplateConfig;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
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

/**
 * The type Guard rest interface.
 */
@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	/**
	 * The constant connection.
	 */
	private final Connection conn = Guard_Connection.getDbconn();
	/**
	 * The constant logger.
	 */
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	/**
	 * The constant dbServer_url.
	 */
	private static final String dbServer_url = String.format("https://%s/api/v1/", Guard_RESTApp.srvdb);
	/**
	 * The constant File path.
	 */
	private static final String fP = URI.create("Guard/src/main/java/it/unitn/APCM/ACME/Guard/Files/").toString();
	/**
	 * The constant encryption algorithm.
	 */
	static final String algorithm = "AES";

	/**
	 * The Secure rest template.
	 */
	private RestTemplate secureRestTemplate = (new SecureRestTemplateConfig("Guard_keystore.jks", "GuardC_truststore.jks")).secureRestTemplate();

	/**
	 * The Jwt utils.
	 */
	@Autowired
	private JWT_Utils JWT_Utils;

	/**
	 * Recursive fetch files array list.
	 *
	 * @param path the path
	 * @return the array list
	 */
	private ArrayList<String> fetch_files(URI path) {
		// Get the path of the directory
		File directoryPath = new File(path.getPath());

		ArrayList<String> files_list = new ArrayList<>();

		if (directoryPath.exists() && directoryPath.isDirectory()) {
			// If the directory exists get the content
			File[] contents = directoryPath.listFiles();

			// Check all the contents
			for (File content : contents) {
				// Check if the content is a file or a directory
				if (content.isFile()) {
					// is a file so add it to the array list
					String file = path.getPath() + content.getName();
					files_list.add(file.replace(fP, ""));
				} else if (content.isDirectory()) {
					// is a directory so call the function recursively
					files_list.addAll(fetch_files(URI.create(path.getPath() + content.getName() + "/")));
				} else {
					// is neither a file nor a directory, return null
					return null;
				}
			}
		}

		return files_list;
	}

	/**
	 * Endpoint to retrieve the available files
	 *
	 * @param email the email of the user
	 * @param jwt   the jwt token of the user
	 * @return the files
	 */
	@GetMapping("/files")
	public ResponseEntity<String> get_files(@RequestParam String email, @RequestHeader String jwt) {

		log.trace("Request for available files from: " + email);

		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		ArrayList<String> files_list = new ArrayList<>();

		// Validate the JWT token
		if (JWT_Utils.validateToken(jwt, email)) {
			// Token is valid, retrieve the files
			files_list = fetch_files(URI.create(fP));
			status = HttpStatus.OK;
		} else {
			// Token is not valid, return unauthorized
			log.error("Unauthorized user");
			status = HttpStatus.UNAUTHORIZED;
		}

		// Create a JSON object
		JSONObject files = new JSONObject();
		try {
			files.put("files", new JSONArray(files_list).toString());
		} catch (JSONException e) {
			status = HttpStatus.INTERNAL_SERVER_ERROR;
			log.error("Error while creating the JSON object: " + e.getMessage());
		}

		// Convert the JSON object to a string
		String response = files.toString();

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to create a new user
	 *
	 * @param email    the email
	 * @param password the password
	 * @param groups   the groups
	 * @param admin    the admin
	 * @return the response entity
	 */
	@GetMapping("/newUser")
	public ResponseEntity<String> createUser(@RequestParam String email, @RequestParam String password,
			@RequestParam String groups, @RequestParam int admin) {

		log.trace("got a request to create a new user");
		Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 32 * 1024, 2);

		// generate hash with argon2
		String encoded_password = encoder.encode(password);
		// System.out.println("generated pass: " + encoded_password);

		// format groups
		groups = groups.replace(",", "\",\"");
		groups = "[\"" + groups + "\"]";
		// System.out.println(groups);

		String response = "error";
		HttpStatus status = HttpStatus.BAD_REQUEST;

		String insertQuery = "INSERT INTO Users(email, pass, groups, admin) VALUES (?,?,?,?)";
		try {
			PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
			prepStatement.setString(1, email);
			prepStatement.setString(2, encoded_password);
			prepStatement.setString(3, groups);
			prepStatement.setInt(4, admin);

			prepStatement.executeUpdate();

			response = "success";
			status = HttpStatus.OK;
		} catch (SQLException e) {
			log.error("User already existent");
		}

		return new ResponseEntity<>(response, new HttpHeaders(), status);
	}

	/**
	 * Endpoint to login
	 *
	 * @param credentials the credentials of the user as JSON
	 * @return the response entity
	 */
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody String credentials) {
		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.UNAUTHORIZED;
		String response = "error";

		String email = null, password = null;
		ObjectMapper objectMapper = new ObjectMapper();
		// Try to parse the JSON object from the request body
		try {
			JsonNode jsonNode = objectMapper.readTree(credentials);

			email = jsonNode.get("email").asText();
			password = jsonNode.get("password").asText();
		} catch (Exception e) {
			status = HttpStatus.INTERNAL_SERVER_ERROR;
			log.error("Error while parsing the JSON object: " + e.getMessage());
		}

		log.trace("Login request from: " + email);

		// Prepare the query to retrieve the password from the db
		String loginQuery = "SELECT pass FROM Users WHERE email=?";
		PreparedStatement preparedStatement;

		String stored_password = null;

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(loginQuery);
			preparedStatement.setString(1, email);
			ResultSet rs = preparedStatement.executeQuery();

			// Get the password from the result set
			if (rs.next())
				stored_password = rs.getString("pass");
		} catch (SQLException e) {
			log.error("Error while retrieving the password from the db: " + e.getMessage());
			throw new RuntimeException(e);
		}

		if (stored_password != null) {
			// Check if the password is valid with argon2
			Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(32, 64, 1, 32 * 1024, 2);

			if (encoder.matches(password, stored_password)) {
				// Password is valid, create the JWT token
				// Get the user privilege
				UserPrivilege userPrivilege = getUserPrivilege(email);
				User user = new User(email, userPrivilege.getGroups(), userPrivilege.getAdmin());
				// Create the JWT token with the user data
				final String jwt = JWT_Utils.generateToken(user);

				// Set the response header and status
				response = "success";
				status = HttpStatus.OK;
				headers.add("jwt", jwt);
			} else {
				// Password is not valid, return unauthorized
				response = "error";
				status = HttpStatus.UNAUTHORIZED;
			}
		} else {
			// User not existing => Default Unauthorized
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to retrieve a file
	 *
	 * @param email the email of the user requesting the file
	 * @param path  the path of the file
	 * @param jwt   the jwt token of the user
	 * @return the file
	 * @throws IOException the io exception
	 */
	@GetMapping(value = "/file")
	public ResponseEntity<ClientResponse> get_file(@RequestParam String email,
			@RequestParam String path, @RequestHeader String jwt) throws IOException {

		log.trace("Request to open file: " + path + " from: " + email);

		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		// Create the response object
		ClientResponse clientResponse = new ClientResponse(path, false, false, "");

		// Check for path traversal attempts
		if (!securePath(fP, path)) {
			return new ResponseEntity<>(clientResponse, headers, status);
		}

		// Validate the JWT token
		if (JWT_Utils.validateToken(jwt, email)) {

			UserPrivilege user = new UserPrivilege(JWT_Utils.extractAdmin(jwt), JWT_Utils.extractGroups(jwt));
			String completePath = URI.create(fP + path).toString();

			long fileSize;
			byte[] allBytes = null;
			try (InputStream inputStream = new FileInputStream(completePath)) {
				// set up buffer
				fileSize = new File(completePath).length();
				if ((int) fileSize != 0) {
					allBytes = new byte[(int) fileSize];
					// read from file and return result
					inputStream.read(allBytes);
				}
				inputStream.close();
			}

			String file_hash = "";
			// get the hash of the file
			if ((int) fileSize != 0) {
				file_hash = (new CryptographyPrimitive()).getHash(allBytes);
			}

			// craft the request to the db interface for the decryption key
			String DB_request_url = dbServer_url + "decryption_key?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&file_hash=" + file_hash +
					"&email=" + email +
					"&user_groups=" + user.getGroups() +
					"&admin=" + user.getAdmin();

			log.trace("Requesting for: " + DB_request_url);

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;

			try {
				// get the response and decide accordingly
				Response res = srt.getForEntity(DB_request_url, Response.class).getBody();

				if (res != null) {
					// Check if the user is authorized to read the file
					if (res.get_auth()) {
						clientResponse.set_auth(true);
						// Check if the user is authorized to write the file
						if (res.get_w_mode()) {
							clientResponse.set_w_mode(true);
						}

						// Decrypt the file and set the response
						if ((int) fileSize != 0) {
							byte[] keyBytes = res.get_key();
							SecretKey decK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
							byte[] textDec = (new CryptographyPrimitive()).decrypt(allBytes, decK);
							clientResponse.set_text(new String(textDec));
						} else {
							clientResponse.set_text("");
						}
						// Set the response status
						status = HttpStatus.OK;
					}
				}
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				clientResponse = null;
				log.error("Error in the response from DB server");
			}
		} else {
			// Token is not valid, return unauthorized
			log.error("Unauthorized user");
			status = HttpStatus.UNAUTHORIZED;
			clientResponse = null;
		}

		return new ResponseEntity<>(clientResponse, headers, status);
	}

	/**
	 * Endpoint to save a file
	 *
	 * @param email         the email of the user requesting to save the file
	 * @param path          the path of the file
	 * @param newTextToSave the new text to save
	 * @param jwt           the jwt token of the user
	 * @return the response entity
	 * @throws IOException the io exception
	 */
	@PostMapping(value = "/file")
	public ResponseEntity<String> save_file(@RequestParam String email,
			@RequestParam String path,
			@RequestBody String newTextToSave, @RequestHeader String jwt) throws IOException {

		log.trace("Request to save new content for file: " + path + " from: " + email);

		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String response = "error";

		// Check for path traversal attempts
		if (!securePath(fP, path)) {
			return new ResponseEntity<>(response, headers, status);
		}

		// Validate the JWT token
		if (JWT_Utils.validateToken(jwt, email)) {

			// Get the user privilege
			UserPrivilege user = new UserPrivilege(JWT_Utils.extractAdmin(jwt), JWT_Utils.extractGroups(jwt));

			// Craft the request to the DB interface
			String DB_request_url = dbServer_url + "decryption_key?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&file_hash=" +
					"&email=" + email +
					"&user_groups=" + user.getGroups() +
					"&admin=" + user.getAdmin();

			log.trace("Requesting for: " + DB_request_url);

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;

			try {
				// get the response and decide accordingly
				Response res = srt.getForEntity(DB_request_url, Response.class).getBody();

				if (res != null) {
					// Check if the user is authorized to write the file
					if (res.get_w_mode() && !newTextToSave.isEmpty()) {
						// Decrypt the file with the retrieved key
						byte[] keyBytes = res.get_key();
						SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, algorithm);
						// Encrypt the new text
						byte[] textEnc = (new CryptographyPrimitive()).encrypt(newTextToSave.getBytes(), encK);

						// Save encrypted file
						String completePath = URI.create(fP + path).toString();
						try (OutputStream outputStream = new FileOutputStream(completePath)) {
							outputStream.write(textEnc, 0, textEnc.length);
							outputStream.flush();
							outputStream.close();
						}

						// Craft the request to the DB interface
						String DB_request2_url = dbServer_url + "saveFile?" +
								"path_hash="
								+ (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8))
								+ "&file_hash=" + (new CryptographyPrimitive()).getHash(textEnc);

						log.trace("Requesting for: " + DB_request2_url);

						// sends the request and capture the response
						String res2 = srt.postForEntity(DB_request2_url, null, String.class).getBody();
						assert res2 != null;
						// Check if the file has been saved
						if (res2.equals("success")) {
							status = HttpStatus.CREATED;
							response = "success";
						}
					}
				}
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				log.error("Error in the response from DB server");
			}
		} else {
			// Token is not valid, return unauthorized
			log.error("Unauthorized user");
			status = HttpStatus.UNAUTHORIZED;
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to create a new file
	 *
	 * @param email     the email of the user requesting to create the file
	 * @param path      the path of the file
	 * @param r_groups  the r groups of the file
	 * @param rw_groups the rw groups of the file
	 * @param jwt       the jwt token of the user
	 * @return the response entity
	 * @throws Exception the exception
	 */
	@GetMapping(value = "/newFile")
	public ResponseEntity<String> new_file(@RequestParam String email,
			@RequestParam String path,
			@RequestParam String r_groups,
			@RequestParam String rw_groups,
			@RequestHeader String jwt) throws Exception {

		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String response = "error";

		// Check for path traversal attempts
		if (!securePath(fP, path)) {
			return new ResponseEntity<>(response, headers, status);
		}

		log.trace("Request to create a new file from: " + email);

		// Validate the JWT token
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
				ResponseEntity<String> ent = srt.postForEntity(DB_request_url, null, String.class);
				String res = ent.getBody();

				// if the response is success, create the file
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
					if (f.createNewFile()) {
						// Set the response header and status
						response = "success";
						status = HttpStatus.CREATED;

					} else {
						throw new ResourceAccessException(
								"File already esisting: " + realpath + splittedPath[indexName]);
					}
				}
			} catch (HttpClientErrorException | HttpServerErrorException e) {
				log.error("Error in the response from DB server");
			} catch (ResourceAccessException | IOException e) {
				log.error("Error in the creation of the file");

				String DB_delete_url = dbServer_url + "deleteFile?" +
						"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8));

				try {
					log.trace("Requesting for: " + DB_delete_url);
					ResponseEntity<String> ent = srt.exchange(DB_delete_url, HttpMethod.DELETE, null, String.class);

					HttpStatusCode res = ent.getStatusCode();
					log.trace("" + res);
					if (res == HttpStatus.OK) {
						log.trace("File deleted");
					} else {
						log.error("Impossible to delete");
					}
				} catch (HttpClientErrorException | HttpServerErrorException ex) {
					log.error("Impossible to delete" + ex.getMessage());
				}
			}
		} else {
			// Token is not valid, return unauthorized
			log.error("Unauthorized user");
			status = HttpStatus.UNAUTHORIZED;
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Endpoint to delete a file
	 *
	 * @param email the email of the user requesting to delete the file
	 * @param path  the path of the file
	 * @param jwt   the jwt token of the user
	 * @return the response entity
	 * @throws IOException the io exception
	 */
	@DeleteMapping(value = "/delete")
	public ResponseEntity<String> delete_file(@RequestParam String email,
			@RequestParam String path, @RequestHeader String jwt) throws IOException {

		log.trace("Request to delete file: " + path + " from: " + email);

		// Set up the response header and status
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String response = "error";

		// Check for path traversal attempts
		if (!securePath(fP, path)) {
			return new ResponseEntity<>(response, headers, status);
		}

		// Validate the JWT token
		if (JWT_Utils.validateToken(jwt, email)) {

			// Get the user privilege
			UserPrivilege user = new UserPrivilege(JWT_Utils.extractAdmin(jwt), JWT_Utils.extractGroups(jwt));

			// Craft the request to the DB interface
			String DB_request_url = dbServer_url + "decryption_key?" +
					"path_hash=" + (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8)) +
					"&file_hash=" +
					"&email=" + email +
					"&user_groups=" + user.getGroups() +
					"&admin=" + user.getAdmin();

			log.trace("Requesting for: " + DB_request_url);

			// sends the request and capture the response
			RestTemplate srt = secureRestTemplate;
			Response res = null;
			try {
				// get the response and decide accordingly
				res = srt.getForEntity(DB_request_url, Response.class).getBody();
			} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException e) {
				log.error("Error in the response from DB server");
			}

			if (res != null) {
				// Check if the user is authorized to write the file
				if (res.get_w_mode()) {

					String completePath = URI.create(fP + path).toString();

					byte[] allBytes = null;
					// Save the content of the file for eventual restore
					try (InputStream inputStream = new FileInputStream(completePath)) {
						// set up buffer
						long fileSize = new File(completePath).length();
						if ((int) fileSize != 0) {
							allBytes = new byte[(int) fileSize];
							// read from file and return result
							inputStream.read(allBytes);
						}
						inputStream.close();
					}

					boolean file_deleted = false;
					boolean file_deleted_DB = false;

					// get the path of the file
					String[] splittedPath = path.split("/");
					int indexName = splittedPath.length - 1;
					String dirPath = "";
					for (int i = 0; i < indexName; i++) {
						dirPath += "/" + splittedPath[i];
					}
					String realpath = URI.create(fP + dirPath).getPath();

					// Try to delete the file
					File file = new File(realpath, splittedPath[indexName]);

					if (file.delete()) {
						file_deleted = true;
					}

					// Check if the file is deleted
					if (file_deleted) {
						log.trace("File: " + path + " deleted");
						// File deleted, request the db to remove the entry
						String DB_delete_url = dbServer_url + "deleteFile?" +
								"path_hash="
								+ (new CryptographyPrimitive()).getHash(path.getBytes(StandardCharsets.UTF_8));

						// Request the db to delete the file
						try {
							log.trace("Requesting for: " + DB_delete_url);
							ResponseEntity<String> ent = srt.exchange(DB_delete_url, HttpMethod.DELETE, null,
									String.class);

							// Check the db response
							HttpStatusCode code = ent.getStatusCode();
							if (code == HttpStatus.OK) {
								// If ok set the response and inform the client that the file has been deleted
								// successfully
								log.trace("File deleted successfully");
								response = "success";
								status = HttpStatus.OK;
								file_deleted_DB = true;
							} else {
								log.error("Impossible to delete");
							}
						} catch (HttpClientErrorException | HttpServerErrorException | ResourceAccessException ex) {
							log.error("Impossible to delete" + ex.getMessage());
						}
					}

					// Check if file is deleted only on the guard and not in the db
					if (file_deleted && !file_deleted_DB) {
						// If so, restore file and abort operation
						File f = new File(completePath);
						if (f.createNewFile()) {
							try (OutputStream outputStream = new FileOutputStream(completePath)) {
								outputStream.write(allBytes, 0, allBytes.length);
								outputStream.flush();
								outputStream.close();
							}
						}
					}
				}
			}
		} else {
			// Token is not valid, return unauthorized
			log.error("Unauthorized user");
			status = HttpStatus.UNAUTHORIZED;
		}

		return new ResponseEntity<>(response, headers, status);
	}

	/**
	 * Gets user privilege from the DB.
	 *
	 * @param email the email
	 * @return the user privilege
	 */
	private UserPrivilege getUserPrivilege(String email) {
		ArrayList<String> groups = null;
		int admin = 0;
		String userQuery = "SELECT groups, admin FROM Users WHERE email=?";
		PreparedStatement preparedStatement;

		// Create the query and retrieve results from user db
		try {
			preparedStatement = conn.prepareStatement(userQuery);
			preparedStatement.setString(1, email);
			ResultSet rs = preparedStatement.executeQuery();

			// Get the groups and admin from the result set
			while (rs.next()) {
				groups = new JSONToArray(rs.getString("groups"));
				admin = rs.getInt("admin");
			}
		} catch (SQLException | JsonProcessingException e) {
			log.error("Error while retrieving the user privilege from the db: " + e.getMessage());
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

	/**
	 * Secure path to check for path traversal attempts.
	 *
	 * @param basePath the base path of the directory of files
	 * @param userPath the user path requested
	 * @return the boolean
	 */
	private boolean securePath(String basePath, String userPath) {
		// Get the path of the directory
		Path path = Paths.get(basePath).normalize();
		// Get the requested path
		Path resolvedPath = path.resolve(userPath).normalize();

		// Check if the resolved path is inside the base path
		if (!resolvedPath.startsWith(path)) {
			log.error("Path traversal attempt detected");
			return false;
		}

		return true;
	}
}