package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.ArrayList;

@SpringBootApplication
public class Guard_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTApp.class);

	static public String srvdb = null;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(Guard_RESTApp.class);

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
				srvdb = real_args.get(0);
				break;
			default:
				log.error("Error in parameters number, some parameter are not parsed");
				throw new IllegalArgumentException("At most 1 parameter could be passed");
		}
		if (srvdb == null) {
			// Leave the default value
			srvdb = "localhost:8091";
		}
		app.run(args);
		log.info("Guard_RESTApp started");
	}
}
