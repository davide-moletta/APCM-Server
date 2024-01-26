package it.unitn.APCM.ACME.DBManager;

import com.fasterxml.jackson.core.JsonProcessingException;

import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * The type Db rest interface.
 */
@RestController
@RequestMapping("/api/v1")
public class DB_RESTInterface {
	/**
	 * The constant conn.
	 */
	// Connection statically instantiated
	private final Connection conn = DB_Connection.getDbconn();
	/**
	 * The constant log.
	 */
	// Logger
	private static final Logger log = LoggerFactory.getLogger(DB_RESTInterface.class);

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 *
	 * @param path_hash  the path hash
	 * @param file_hash  the file hash
	 * @param email      the email
	 * @param user_group the user group
	 * @param admin      the admin
	 * @return the key
	 */
	@GetMapping("/decryption_key")
	public ResponseEntity<Response> get_key(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "user_groups") String user_group,
			@RequestParam(value = "admin") String admin) {

		// Setup the response and headers
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		Response res = new Response(path_hash, email, false, false, null);
		ArrayList<String> user_groups = new ArrayList<String>(Arrays.asList(user_group.split(",")));

		log.trace("Request for decryption key from: " + email);

		// Prepare the query to get the file info
		String getInfoQuery = "SELECT encryption_key, path_hash, owner, rw_groups, r_groups, file_hash FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();

			while (rs.next()) {
				// Check if there are more than one result
				if (rs.isFirst()) {
					// Check if the file is corrupted
					if (file_hash.equals("") || rs.getString("file_hash").equals(file_hash)) {
						// Get the encryption key
						byte[] encryptionKey = null;
						encryptionKey = (rs.getBytes("encryption_key"));

						// Check if the user is authorized to access the file
						if (admin.equals("1") || rs.getString("owner").equals(email)) {
							log.trace("User is an admin or the owner of the file");
							res.set_auth(true);
							res.set_w_mode(true);
						} else {
							ArrayList<String> rw_groups = new JSONToArray(rs.getString("rw_groups"));
							ArrayList<String> r_groups = new JSONToArray(rs.getString("r_groups"));

							// If user is neither admin nor owner check the groups
							for (String g : user_groups) {
								// Check if the user is in the rw_groups or only in the r groups
								if (rw_groups.contains(g)) {
									res.set_auth(true);
									res.set_w_mode(true);
									break;
								} else if (r_groups.contains(g)) {
									res.set_auth(true);
									res.set_w_mode(false);
								}
							}
						}

						if (res.get_auth() && encryptionKey != null) {
							// If the user is authorized, decrypt the encryption key and set the response
							byte[] decKey = (new CryptographyPrimitive()).decrypt(encryptionKey,
									DB_RESTApp.masterKey);
							res.set_key(decKey);
							status = HttpStatus.CREATED;
						} else {
							log.error("User not authorized");
							status = HttpStatus.UNAUTHORIZED;
						}
					} else {
						log.error("File corrupted");
						throw new ResponseStatusException(HttpStatus.CONFLICT, "File corrupted");
					}
				} else {
					// more than one result
					// possible collision of hash
					log.error("Found more than one path_hash, possible collision or multiple row for one file");
					throw new ResponseStatusException(HttpStatus.CONFLICT, "HASH collision");
				}
			}
		} catch (SQLException | JsonProcessingException e) {
			log.error("Error in getting file info from the db: " + e.getMessage());
			throw new RuntimeException(e);
		}

		return new ResponseEntity<>(res, headers, status);
	}

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 *
	 * @param path_hash the path hash
	 * @param path      the path
	 * @param email     the email
	 * @param r_groups  the r groups
	 * @param rw_groups the rw groups
	 * @return the response entity
	 */
	@PostMapping("/newFile")
	public ResponseEntity<String> new_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "path") String path,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "r_groups") String r_groups,
			@RequestParam(value = "rw_groups") String rw_groups) {

		// Setup the response and headers
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		boolean error = false;
		String res = "error";

		log.trace("Request to create a new file from: " + email);

		// Prepare the query to check if the file already exists
		String getInfoQuery = "SELECT path_hash FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			// Execute the query and check if it was successful
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				error = true;
				log.error("File already existing");
				throw new ResponseStatusException(HttpStatus.CONFLICT, "File already existing");
			}
		} catch (SQLException e) {
			log.error("Error in checking if the file already exists: " + e.getMessage());
			throw new RuntimeException(e);
		}

		// If the file doesn't exist, insert it
		if (!error) {
			// generate new key
			SecretKey sK = (new CryptographyPrimitive()).getSymmetricKey();
			byte[] enc_key = (new CryptographyPrimitive()).encrypt(sK.getEncoded(), DB_RESTApp.masterKey);

			// Format the groups in JSON format
			r_groups = r_groups.replace(",", "\",\"");
			r_groups = "[\"" + r_groups + "\"]";

			rw_groups = rw_groups.replace(",", "\",\"");
			rw_groups = "[\"" + rw_groups + "\"]";

			// Prepare the query to insert the file
			String insertQuery = "INSERT INTO Files(path_hash, file_hash, path, owner, rw_groups, r_groups, encryption_key) VALUES (?,?,?,?,?,?,?)";
			try {
				// Set the parameters
				PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
				prepStatement.setString(1, path_hash);
				prepStatement.setString(2, "");
				prepStatement.setString(3, path);
				prepStatement.setString(4, email);
				prepStatement.setString(5, rw_groups);
				prepStatement.setString(6, r_groups);
				prepStatement.setBytes(7, enc_key);

				// Execute the query and check if it was successful
				if (prepStatement.executeUpdate() != 0) {
					status = HttpStatus.CREATED;
					res = "success";
				}
			} catch (SQLException e) {
				log.error("Error in inserting file in the db. Path_hash is not unique");
			}
		}

		return new ResponseEntity<>(res, headers, status);
	}

	/**
	 * Endpoint to save new file Hash
	 *
	 * @param path_hash the path hash
	 * @param file_hash the file hash
	 * @return the response entity
	 */
	@PostMapping("/saveFile")
	public ResponseEntity<String> save_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash) {

		// Setup the response and headers
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String res = "error";

		log.trace("Request to save a file");

		// Prepare the query to update the file hash
		String updateHashQuery = "UPDATE Files SET file_hash = ? WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			// Set the parameters
			ps = conn.prepareStatement(updateHashQuery);
			ps.setString(1, file_hash);
			ps.setString(2, path_hash);
			// Execute the query and check if it was successful
			if (ps.executeUpdate() != 0) {
				res = "success";
				status = HttpStatus.CREATED;
			}
		} catch (SQLException e) {
			log.error("Error in updating file hash in the db: " + e.getMessage());
			throw new RuntimeException(e);
		}

		return new ResponseEntity<>(res, headers, status);
	}

	/**
	 * Endpoint to delete a file
	 *
	 * @param path_hash the path hash
	 * @return the response entity
	 */
	@DeleteMapping("/deleteFile")
	public ResponseEntity<String> delete_File(@RequestParam(value = "path_hash") String path_hash) {

		// Setup the response and headers
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
		String res = "error";

		log.trace("Request to delete a file");

		// Prepare the query to delete the file
		String updateHashQuery = "DELETE FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			// Set the parameters
			ps = conn.prepareStatement(updateHashQuery);
			ps.setString(1, path_hash);
			// Execute the query and check if it was successful
			if (ps.executeUpdate() != 0) {
				res = "success";
				status = HttpStatus.OK;
			}
		} catch (SQLException e) {
			log.error("Error in deleting file in the db: " + e.getMessage());
			throw new RuntimeException(e);
		}

		return new ResponseEntity<>(res, headers, status);
	}
}
