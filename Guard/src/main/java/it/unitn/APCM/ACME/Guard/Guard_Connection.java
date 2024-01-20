package it.unitn.APCM.ACME.Guard;

import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;

public class Guard_Connection {
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_users.sqlite");
	private static final Logger log = LoggerFactory.getLogger(Guard_Connection.class);

	public static Connection getDbconn() {
		log.trace("Connection to db_users requested");
		return dbconn.getConn();
	}
}
