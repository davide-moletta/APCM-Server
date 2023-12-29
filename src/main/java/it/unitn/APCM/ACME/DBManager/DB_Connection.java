package it.unitn.APCM.ACME.DBManager;

import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;

import java.sql.Connection;

public class DB_Connection {
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_files.sqlite");

	public static Connection getDbconn() {
		return dbconn.getConn();
	}
}
