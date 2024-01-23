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

@RestController
@RequestMapping("/api/v1")
public class DB_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = DB_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(DB_RESTInterface.class);

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 */
	@GetMapping("/decryption_key")
	public ResponseEntity<Response> get_key(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "user_groups") String user_group,
			@RequestParam(value = "admin") String admin) {

		Response res = new Response(path_hash, email, false, false, null);
		ArrayList<String> user_groups = new ArrayList<String>(Arrays.asList(user_group.split(",")));
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.UNAUTHORIZED;

		String getInfoQuery = "SELECT encryption_key, path_hash, owner, rw_groups, r_groups, file_hash FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();

			while (rs.next()) {
				if (rs.isFirst()) {
					if (file_hash.equals("") || rs.getString("file_hash").equals(file_hash)) {
						byte[] encryptionKey = null;
						encryptionKey = (rs.getBytes("encryption_key"));

						if (admin.equals("1") || rs.getString("owner").equals(email)) {
							log.trace("User is an admin or the owner of the file");
							res.set_auth(true);
							res.set_w_mode(true);
						} else {
							ArrayList<String> rw_groups = new JSONToArray(rs.getString("rw_groups"));
							ArrayList<String> r_groups = new JSONToArray(rs.getString("r_groups"));

							for (String g : user_groups) {
								if (rw_groups.contains(g)) {
									res.set_auth(true);
									res.set_w_mode(true);
									break;
								} else if (r_groups.contains(g)) {
									res.set_auth(true);
									res.set_w_mode(false);
									// no break because can be also present after another g in the rw_groups
								}
							}
						}

						if (res.get_auth() && encryptionKey != null) {
							byte[] decKey = (new CryptographyPrimitive()).decrypt(encryptionKey,
									DB_RESTApp.masterKey);
							res.set_key(decKey);
							status = HttpStatus.CREATED;
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
			throw new RuntimeException(e);
		}

		return new ResponseEntity<>(res, headers, status);
	}

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 */
	@PostMapping("/newFile")
	public ResponseEntity<String> new_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "path") String path,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "r_groups") String r_groups,
			@RequestParam(value = "rw_groups") String rw_groups) {

		boolean error = false;
		String res = "error";
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		String getInfoQuery = "SELECT path_hash FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				error = true;
				log.error("File already existing");
				throw new ResponseStatusException(HttpStatus.CONFLICT, "File already existing");
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		if (!error) {
			// generate new key
			SecretKey sK = (new CryptographyPrimitive()).getSymmetricKey();
			byte[] enc_key = (new CryptographyPrimitive()).encrypt(sK.getEncoded(), DB_RESTApp.masterKey);

			r_groups = r_groups.replace(",", "\",\"");
			r_groups = "[\"" + r_groups + "\"]";

			rw_groups = rw_groups.replace(",", "\",\"");
			rw_groups = "[\"" + rw_groups + "\"]";

			String insertQuery = "INSERT INTO Files(path_hash, file_hash, path, owner, rw_groups, r_groups, encryption_key) VALUES (?,?,?,?,?,?,?)";
			try {
				PreparedStatement prepStatement = conn.prepareStatement(insertQuery);
				prepStatement.setString(1, path_hash);
				prepStatement.setString(2, "");
				prepStatement.setString(3, path);
				prepStatement.setString(4, email);
				prepStatement.setString(5, rw_groups);
				prepStatement.setString(6, r_groups);
				prepStatement.setBytes(7, enc_key);

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
	 * Endpoint for saving new file Hash
	 */
	@PostMapping("/saveFile")
	public ResponseEntity<String> save_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash) {

		String res = "error";
		HttpHeaders headers = new HttpHeaders();
		HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

		String updateHashQuery = "UPDATE Files SET file_hash = ? WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(updateHashQuery);
			ps.setString(1, file_hash);
			ps.setString(2, path_hash);
			if (ps.executeUpdate() != 0) {
				res = "success";
				status = HttpStatus.CREATED;
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		return new ResponseEntity<>(res, headers, status);
	}
}
