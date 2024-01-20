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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

@RestController
@RequestMapping("/api/v1")
public class DB_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = DB_Connection.getDbconn();
	private static final Logger log = LoggerFactory.getLogger(DB_RESTInterface.class);
	
	/**
	 * Endpoint for list all file for a specific owner
	 */
	@GetMapping("/files")
	public Map<String, String> get_files(@RequestParam(value = "owner") String owner) {
		HashMap<String, String> res = new HashMap<>();
		String selectQuery = "SELECT path_hash, path FROM Files WHERE owner = ?";
		PreparedStatement preparedStatement;
		try {
			preparedStatement = conn.prepareStatement(selectQuery);
			preparedStatement.setString(1, owner);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				res.put("path_hash", rs.getString("path_hash"));
				res.put("path", rs.getString("path"));
			}
		} catch (SQLException e) {
			log.error("Impossible retrieving the files");
		}
		return res;
	}

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 */        
	@GetMapping("/decryption_key")
	public ResponseEntity<Response> get_key(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash,
			@RequestParam(value = "open") boolean open,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "user_groups") String user_group,
			@RequestParam(value = "admin") String admin) {
				
		Response res = new Response(path_hash, email, false, false, null);
		ArrayList<String> user_groups = new ArrayList<String>(Arrays.asList(user_group.split(",")));

		String getInfoQuery = "SELECT path_hash, owner, rw_groups, r_groups, file_hash FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				if (rs.isFirst()) {
					if(open == false || rs.getString("file_hash").equals(file_hash)){
						if (admin.equals("1")) {
							log.trace("User is an admin");
							res.set_auth(true);
							res.set_w_mode(true);
						} else if (rs.getString("owner").equals(email)) {
							log.trace("User is the owner for the file requested");
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
	
		if (res.get_auth()) {
			// Check ok then return key
			String selectQuery = "SELECT encryption_key FROM Files WHERE path_hash = ?";
			try {
				ps = conn.prepareStatement(selectQuery);
				ps.setString(1, path_hash);
				ResultSet rs = ps.executeQuery();

				byte[] encryptionKey = null;

				while (rs.next()) {
					encryptionKey = (rs.getBytes("encryption_key"));
				}

				if (encryptionKey != null) {
					byte[] decKey = (new CryptographyPrimitive()).decrypt(encryptionKey, DB_RESTApp.masterKey);
				 	res.set_key(decKey);
				}
			} catch (SQLException e) {
				throw new RuntimeException(e);
			}
		} 

		HttpHeaders headers = new HttpHeaders();
		
		ResponseEntity<Response> entity = new ResponseEntity<>(res, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 */
	@GetMapping("/newFile")
	public ResponseEntity<String> new_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "path") String path,
			@RequestParam(value = "email") String email,
			@RequestParam(value = "r_groups") String r_groups,
			@RequestParam(value = "rw_groups") String rw_groups) {

		boolean error = false;
		String res = "error";

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

		if(!error){
			//generate new key 
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

				prepStatement.executeUpdate();

				res = "success";
			} catch (SQLException e) {
				log.error("Error in inserting file in the db. Path_hash is not uniques");
			}
		}

		HttpHeaders headers = new HttpHeaders();

		ResponseEntity<String> entity = new ResponseEntity<>(res, headers, HttpStatus.CREATED);

		return entity;
	}

	/**
	 * Endpoint for saving new file Hash
	 */
	@PostMapping("/saveFile")
	public ResponseEntity<String> save_File(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "file_hash") String file_hash) {

		boolean error = false;
		String res = "error";

		String updateHashQuery = "UPDATE Files SET file_hash = ? WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(updateHashQuery);
			ps.setString(1, file_hash);
			ps.setString(2, path_hash);
			int rs = ps.executeUpdate();
			if(rs == 1){
				res = "success";
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> entity = new ResponseEntity<>(res, headers, HttpStatus.CREATED);

		return entity;
	}
}
