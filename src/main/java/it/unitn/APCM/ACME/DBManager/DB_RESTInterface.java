package it.unitn.APCM.ACME.DBManager;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
public class DB_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = DB_Connection.getDbconn();

	@GetMapping("/files")
	public String get_files(@RequestParam(value = "owner", defaultValue = "test") String owner) {
		String res = null;
		String selectQuery = "SELECT path_hash, path FROM Files WHERE owner = ?";
		PreparedStatement preparedStatement;
		try {
			preparedStatement = conn.prepareStatement(selectQuery);
			preparedStatement.setString(1, owner);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				res = ("["+rs.getString("path_hash")+"]" +  "\t" +
						rs.getString("path"));
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return res;
	}


	/*
	 * public class DB_RESTInterface {

	@RequestMapping(path = "/files", method = RequestMethod.GET)
	public String login(@RequestParam String user, @RequestParam String groups, @RequestParam String path) {

		return "user " + user + " from groups: " + groups + " wants to open: " + path;
	}
}



	 */
}
