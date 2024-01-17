package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

import ch.qos.logback.core.model.INamedModel;
import it.unitn.APCM.ACME.DBManager.DB_RESTApp;
import it.unitn.APCM.ACME.ServerCommon.ClientResponse;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;

import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@RestController
@RequestMapping("/api/v1")
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTInterface.class);
	private static final String dbServer_url = "http://localhost:8091/api/v1/decryption_key?";
	private static final String filePath = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\Files";
	private static final String fP = "src\\main\\java\\it\\unitn\\APCM\\ACME\\Guard\\";
	// encryption algorithm
	// CHECK TYPE OF ENCRYPTION ALGORITHM
	static final String cipherString = "ChaCha20";
	// length of key in bytes
	static final int keyByteLen = 20;
	// IV length
	static final int IVLEN = 12;

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
						SecretKey decK = new SecretKeySpec(keyBytes, 0, keyBytes.length, cipherString);
						byte[] textDec = decryptFile(fileContent.getBytes(), decK);
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
						SecretKey encK = new SecretKeySpec(keyBytes, 0, keyBytes.length, cipherString);
						byte[] textEnc = encryptFile(newTextToSave.getBytes(), encK);
						//Encrypt the file
						FileOutputStream fOut = new FileOutputStream(fP + path);
						IOUtils.write(new String(textEnc), fOut, StandardCharsets.UTF_8);
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

	private byte[] encryptFile(byte[] text, SecretKey encKey) {
		// check that there is some data to encrypt
		if (text.length == 0) {
			log.error("No text to encrypt");
			return null;
		}
		try {
			// Create the cipher
			Cipher cipher = Cipher.getInstance(cipherString);
			// Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, encKey);

			// Retrieve the parameters used during encryption
			// they will be needed for decryption
			byte[] iv = cipher.getIV();

			// Encrypt the input data
			byte[] ciphertext = cipher.doFinal(text);

			// set output
			byte[] encryptedText = new byte[iv.length + ciphertext.length];
			// first part is the IV
			System.arraycopy(iv, 0, encryptedText, 0, IVLEN);
			// second part is the ciphertext
			System.arraycopy(ciphertext, 0, encryptedText, IVLEN, ciphertext.length);

			log.trace("Encrypted text");
			return encryptedText;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			log.error("Encryption failed: " + e);
			return null;
		}
	}

	private byte[] decryptFile(byte[] encText, SecretKey decKey) {
		// check that there is some data to decrypt
		if (encText.length == 0) {
			log.error("No encryption key to decrypt");
			return null;
		}
		try {
			byte[] text;
			// Create the cipher
			Cipher cipher = Cipher.getInstance(cipherString);
			// Retrieve the parameters used during encryption to properly
			// initialize the cipher for decryption
			byte[] iv = new byte[IVLEN];
			byte[] ciphertext = new byte[encText.length - IVLEN];
			// first part is the IV
			System.arraycopy(encText, 0, iv, 0, IVLEN);
			// second part is the ciphertext
			System.arraycopy(encText, IVLEN, ciphertext, 0, ciphertext.length);
			// initialize parameters
			// !!! this is specific for ChaCha20
			AlgorithmParameterSpec chachaSpec = new ChaCha20ParameterSpec(iv, 1);
			// Initialize cipher for decryption
			cipher.init(Cipher.DECRYPT_MODE, decKey, chachaSpec);
			// Decrypt the input data
			text = cipher.doFinal(ciphertext);

			// give feedback
			log.trace("Key decrypted");

			return text;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			// in case of error show error dialog and print to console
			log.error("Decryption failed");
			return null;
		}
	}
}