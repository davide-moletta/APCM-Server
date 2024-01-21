package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import it.unitn.APCM.ACME.DBManager.SSS.Shamir;

import java.io.IOException;
import java.util.*;

import javax.crypto.SecretKey;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		String sss_path = null;
		ArrayList<String> real_args = new ArrayList<>(1);
		// Exclude Spring params
		for (String a : args) {
			if (a != null && !a.startsWith("--")) {
				real_args.add(a);
			}
		}
		switch (real_args.size()) {
			case 0:
				// Use default values
				break;
			case 1:
				// parameter that we want
				sss_path = real_args.get(0);
				break;
			default:
				log.error("Error in parameters number, some parameter are not parsed");
				throw new IllegalArgumentException("At most 1 parameter could be passed");
		}
		Shamir sh = new Shamir();
		try {
			//System.setProperty("javax.net.debug", "ssl:handshake"); // For debug
			masterKey = sh.getMasterSecret(sss_path);
			app.run(args);
			log.info("DB_RESTApp started");
		}
		catch (IOException | NullPointerException e) {
			log.error(e.toString());
		}
	}
}
