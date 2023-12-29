package it.unitn.APCM.ACME.Guard;

import it.unitn.APCM.ACME.ServerCommon.JDBC_Connection;

import java.sql.Connection;

public class Guard_Connection {
	private static final JDBC_Connection dbconn = new JDBC_Connection("db_users.sqlite");

	public static Connection getDbconn() {
		return dbconn.getConn();
	}
}
