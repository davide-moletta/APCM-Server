package it.unitn.APCM.ACME.ServerCommon;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;

/**
 * Class to connect the DB side of the project
 */
public class JDBC_Connection {
	/**
	 * The constant log.
	 */
// Define a logger for the class
	private static final Logger log = LoggerFactory.getLogger(JDBC_Connection.class);

	/**
	 * The Conn.
	 */
// Define Connection to DB
	private Connection conn = null;

	/**
	 * Instantiates a new Jdbc connection.
	 *
	 * @param file the file
	 */
	public JDBC_Connection(String file) {
		connect(file);
	}

	/**
	 * Gets conn.
	 *
	 * @return the conn
	 */
	public Connection getConn() {
		return conn;
	}

	/**
	 * Connect to the db_files database
	 *
	 * @param file the file
	 */
	private void connect(String file) {
		try {
			// db_files uri given in the resource path
			String url = "jdbc:sqlite::resource:" + file;
			// create a connection to the database
			conn = DriverManager.getConnection(url);

			log.info("Connection to SQLite has been established.");

		} catch (SQLException e) {
			log.error(e.getMessage());
		}
	}
}
