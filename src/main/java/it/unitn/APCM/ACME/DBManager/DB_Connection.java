package it.unitn.APCM.ACME.DBManager;

import it.unitn.APCM.ACME.Guard.Guard_Connection;
import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;

public class DB_Connection {
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_files.sqlite");
	private static final Logger log = LoggerFactory.getLogger(DB_Connection.class);

	public static Connection getDbconn() {
		log.trace("Connection to db_files requested");
		return dbconn.getConn();
	}
}
