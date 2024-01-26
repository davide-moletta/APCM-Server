package it.unitn.APCM.ACME.Guard;

import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;

/**
 * The type Guard connection.
 * Used to connect to the sqlite database of users
 */
public class Guard_Connection {
	/**
	 * The constant dbconn.
	 */
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_users.sqlite");
	/**
	 * The constant log.
	 */
	private static final Logger log = LoggerFactory.getLogger(Guard_Connection.class);

	/**
	 * Gets dbconn.
	 *
	 * @return the dbconn
	 */
	public static Connection getDbconn() {
		log.trace("Connection to db_users requested");
		return dbconn.getConn();
	}
}
