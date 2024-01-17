package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import it.unitn.APCM.ACME.DBManager.SSS.Shamir;
import it.unitn.APCM.ACME.ServerCommon.GenKey;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

import javax.crypto.SecretKey;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		HashMap<String, Object> properties = new HashMap<String, Object>(2);
		properties.put("server.port", "8091");
		properties.put("spring.application.name", "DBManager_RESTApp");
		app.setDefaultProperties(properties);
		app.run(args);
		Shamir sh = new Shamir();
		masterKey = sh.getMasterSecret();
		log.info("DB_RESTApp started");
		changeValue();
	}

	private static final Connection conn = DB_Connection.getDbconn();

	// Test to set the encryption key of the file (not encrypted with master key)
	private static void changeValue(){
		GenKey gen = new GenKey();
		String key = gen.getFixedSymmetricKey();
		String selectQuery = "UPDATE Files SET encryption_key = ? WHERE 1 = 1";
		PreparedStatement preparedStatement;
		try {
			preparedStatement = conn.prepareStatement(selectQuery);
			preparedStatement.setString(1, key);
			int rs = preparedStatement.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
}
