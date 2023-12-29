package it.unitn.APCM.ACME.ServerCommon;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.sql.*;

/**
 * Class to connect the DB side of the project
 * @author Edoardo Mich
 */
public class DB_Connection {
	// Define a logger for the class
	private static final Logger log = LoggerFactory.getLogger(DB_Connection.class);

	// Define Connection to DB
	private static Connection conn = null;

	/**
	 * Connect to the db_files database
	 */
	public static void connect(String file) {
		try {
			// db_files uri
			String url = "jdbc:sqlite:"+file;
			// create a connection to the database
			conn = DriverManager.getConnection(url);

			log.info("Connection to SQLite has been established.");

		} catch (SQLException e) {
			log.error(e.getMessage());
		}
	}

	/**
	 * Disconnect from the db_files database
	 */
	private static void disconnect() {
		try {
			if (conn != null) {
				conn.close();
			}
		} catch (SQLException ex) {
			log.error(ex.getMessage());
		}
	}

	/**
	 * Only for testing the connection
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		String file = args[0];
		if (file != null) {
			connect(file);
			String insertQuery = "SELECT * from Files";
			PreparedStatement preparedStatement = null;
			try {
				preparedStatement = conn.prepareStatement(insertQuery);
				ResultSet rs = preparedStatement.executeQuery();

				while (rs.next()) {
					System.out.println(rs.getString("owner") +  "\t" +
							rs.getString("path"));
				}
			} catch (SQLException e) {
				throw new RuntimeException(e);
			}
			disconnect();
		}
	}


}
