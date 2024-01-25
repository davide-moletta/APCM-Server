package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.*;

import org.mitre.secretsharing.Part;
import org.mitre.secretsharing.Secrets;
import org.mitre.secretsharing.codec.PartFormats;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		//String sss_path = null;
		ArrayList<String> real_args = new ArrayList<>(1);
		// Exclude Spring params
		for (String a : args) {
			if (a != null && !a.startsWith("--")) {
				real_args.add(a);
			}
		}

		Part[] parts = null;

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
			byte[] keyByte = Secrets.join(parts);
			masterKey =  new SecretKeySpec(keyByte, 0, keyByte.length, "AES");
			System.out.println(new String(keyByte)); 
			app.run(args);
			log.info("DB_RESTApp started");
		}
		catch (NullPointerException e) {
			log.error(e.toString());
		}
	}
}
