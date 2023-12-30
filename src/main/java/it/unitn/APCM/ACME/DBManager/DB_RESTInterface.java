package it.unitn.APCM.ACME.DBManager;

import com.fasterxml.jackson.core.JsonProcessingException;
import it.unitn.APCM.ACME.ServerCommon.JSONToArray;
import it.unitn.APCM.ACME.ServerCommon.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

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
			throw new RuntimeException(e);
		}
		return res;
	}

	/**
	 * Endpoint for getting the password of the specified file if authorized
	 */
	@GetMapping("/decryption_key")
	public ResponseEntity<Response> get_key(@RequestParam(value = "path_hash") String path_hash,
			@RequestParam(value = "user") String user,
			@RequestParam(value = "user_groups") String user_group,
			@RequestParam(value = "admin") String admin,
			@RequestParam(value = "id") int id) {

		Response res = new Response();
		res.set_auth(false);
		res.set_w_mode(false);
		res.set_email(user);
		res.set_path_hash(path_hash);
		res.set_id(id);

		ArrayList<String> user_groups = new ArrayList<String>(Arrays.asList(user_group.split(",")));

		String getInfoQuery = "SELECT path_hash, owner, rw_groups, r_groups FROM Files WHERE path_hash = ?";
		PreparedStatement ps;
		try {
			ps = conn.prepareStatement(getInfoQuery);
			ps.setString(1, path_hash);
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				if (rs.isFirst()) {
					if (admin.equals("1")) {
						log.trace("User is an admin");
						res.set_auth(true);
						res.set_w_mode(true);
					} else if (rs.getString("owner").equals(user)) {
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
			String selectQuery = "SELECT path_hash, encryption_key FROM Files WHERE path_hash = ?";
			try {
				ps = conn.prepareStatement(selectQuery);
				ps.setString(1, path_hash);
				ResultSet rs = ps.executeQuery();

				while (rs.next()) {
					res.set_key(rs.getString("encryption_key"));
				}
			} catch (SQLException e) {
				throw new RuntimeException(e);
			}
		} else {
			res.set_key("noKey");
		}

		HttpHeaders headers = new HttpHeaders();

		ResponseEntity<Response> entity = new ResponseEntity<>(res, headers, HttpStatus.CREATED);

		return entity;
	}
}
