package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import it.unitn.APCM.ACME.DBManager.SSS.Shamir;

import java.io.IOException;
import java.util.Map;
import java.util.Properties;

import javax.crypto.SecretKey;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		String sss_path = "SSS.txt";
		switch (args.length) {
			case 0:
				// Use default values
				break;
			case 1:
				sss_path = args[0];
				break;
			default:
				log.error("Error in parameters");
				throw new IllegalArgumentException("At most 1 parameter could be passed");
		}
		Shamir sh = new Shamir();
		try {
			masterKey = sh.getMasterSecret(sss_path);
			app.run(args);
			log.info("DB_RESTApp started");
		}
		catch (IOException e) {
			log.error(e.toString());
		}
	}
}
