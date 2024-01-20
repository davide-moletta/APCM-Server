package it.unitn.APCM.ACME.Guard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Map;

@SpringBootApplication
public class Guard_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(Guard_RESTApp.class);

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(Guard_RESTApp.class);
		String srv_port = "8090";
		String srv_app = "Guard_RESTApp";
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
			default:
				log.error("Error in parameters");
				throw new IllegalArgumentException("At most 2 parameter could be passed");
		}

		app.setDefaultProperties(Map.of("server.port", srv_port, "spring.application.name", srv_app));
		app.run(args);
		log.info("Guard_RESTApp started");
	}
}
