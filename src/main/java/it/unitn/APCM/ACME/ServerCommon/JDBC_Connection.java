package it.unitn.APCM.ACME.ServerCommon;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.sql.*;

/**
 * Class to connect the DB side of the project
 */
public class JDBC_Connection {
	// Define a logger for the class
	private static final Logger log = LoggerFactory.getLogger(JDBC_Connection.class);

	// Define Connection to DB
	private Connection conn = null;

	public JDBC_Connection(String file) {
		connect(file);
	}

	public Connection getConn() {
		return conn;
	}

	/**
	 * Connect to the db_files database
	 */
	private void connect(String file) {
		try {
			// db_files uri
			String url = "jdbc:sqlite:" + file;
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
	private void disconnect() {
		try {
			if (conn != null) {
				conn.close();
			}
		} catch (SQLException ex) {
			log.error(ex.getMessage());
		}
	}
}
