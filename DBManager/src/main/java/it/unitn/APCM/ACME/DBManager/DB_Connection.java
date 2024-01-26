package it.unitn.APCM.ACME.DBManager;

import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;

/**
 * The type Db connection.
 */
// Used to connect to the sqlite database of files
public class DB_Connection {
	/**
	 * The constant dbconn.
	 */
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_files.sqlite");
	/**
	 * The constant log.
	 */
	private static final Logger log = LoggerFactory.getLogger(DB_Connection.class);

	/**
	 * Gets dbconn.
	 *
	 * @return the dbconn
	 */
	public static Connection getDbconn() {
		log.trace("Connection to db_files requested");
		return dbconn.getConn();
	}
}
