package it.unitn.APCM.ACME.Servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;

/**
 * Class to connect the DB side of the project
 * @author Edoardo Mich
 */
public class DB_Manager {
	/**
	 * Connect to the db_files database
	 */
	private static final Logger log = LoggerFactory.getLogger(DB_Manager.class);

	public static void connect() {
		Connection conn = null;
		try {
			// db_files uri
			String url = "jdbc:sqlite:db_files.sqlite";
			// create a connection to the database
			conn = DriverManager.getConnection(url);

			log.info("Connection to SQLite has been established.");

			String insertQuery = "SELECT * from Files";
			PreparedStatement preparedStatement = conn.prepareStatement(insertQuery);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				System.out.println(rs.getString("owner") +  "\t" +
						rs.getString("path"));
			}
		} catch (SQLException e) {
			log.error(e.getMessage());
		} finally {
			try {
				if (conn != null) {
					conn.close();
				}
			} catch (SQLException ex) {
				log.error(ex.getMessage());
			}
		}
	}
	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		connect();
	}
}
