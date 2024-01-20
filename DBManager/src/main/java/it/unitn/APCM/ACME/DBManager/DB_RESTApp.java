package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import it.unitn.APCM.ACME.DBManager.SSS.Shamir;

import java.io.IOException;
import java.util.Map;

import javax.crypto.SecretKey;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		String srv_port = "8091";
		String srv_app = "DBManager_RESTApp";
		String sss_path = "SSS.txt";
		switch (args.length) {
			case 0:
				// Use default values
				break;
			case 1:
				srv_port = args[0];
				break;
			case 2:
				srv_port = args[0];
				srv_app = args[1];
				break;
			case 3:
				srv_port = args[0];
				srv_app = args[1];
				sss_path = args[2];
				break;
			default:
				log.error("Error in parameters");
				throw new IllegalArgumentException("At most 3 parameter could be passed");
		}
		Shamir sh = new Shamir();
		try {
			masterKey = sh.getMasterSecret(sss_path);
			app.setDefaultProperties(Map.of("server.port", srv_port, "spring.application.name", srv_app));
			app.run(args);
			log.info("DB_RESTApp started");
		}
		catch (IOException e) {
			log.error(e.toString());
		}
	}
}
