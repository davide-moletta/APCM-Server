package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

import java.util.*;

import org.mitre.secretsharing.Part;
import org.mitre.secretsharing.Secrets;
import org.mitre.secretsharing.codec.PartFormats;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * The type DB rest app.
 */
@SpringBootApplication
public class DB_RESTApp {
	/**
	 * The constant logger.
	 */
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	/**
	 * The constant masterKey used to decrypt file keys.
	 */
	protected static SecretKey masterKey;

	/**
	 * The entry point of application.
	 *
	 * @param args the input arguments which are specified in the launch.json file
	 */
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		ArrayList<String> real_args = new ArrayList<>(1);
		// Exclude Spring params
		for (String a : args) {
			if (a != null && !a.startsWith("--")) {
				real_args.add(a);
			}
		}

		Part[] parts = null;

		// Get the Shamir key parts from the args 
		if(real_args.size() < 3){
			log.error("At least 3 keys are required");
			throw new IllegalArgumentException("At least 3 keys are required");
		} else {
			parts = new Part[real_args.size()];

			for(int i = 0; i < real_args.size(); i++){
				parts[i] = PartFormats.parse(real_args.get(i));
			}
		}

		try {
			// Generate the Shamir key from the retrieved parts
			byte[] keyByte = Secrets.join(parts);
			SecretKey shamirKey =  new SecretKeySpec(keyByte, 0, keyByte.length, "AES");
			// Decrypt the encrypted master key with the Shamir key
			String effEncKey = System.getenv("EFFECTIVE_ENCRYPTED_KEY");
			if (effEncKey != null) {
				byte[] effEncKeyBytes = Base64.getDecoder().decode(effEncKey);
				byte[] masterKeyByte = (new CryptographyPrimitive()).decrypt(effEncKeyBytes, shamirKey);
				// Instantiate the master key
				masterKey = new SecretKeySpec(masterKeyByte, 0, masterKeyByte.length, "AES");

				// Start the application
				app.run(args);
				log.info("DB_RESTApp started");
			}
			else {
				log.error("EFFECTIVE_ENCRYPTED_KEY envvar must be present");
			}
		}
		catch (NullPointerException e) {
			log.error("Failed in starting the application" + e.toString());
		}
	}
}
