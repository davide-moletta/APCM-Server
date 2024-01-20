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
		app.run(args);
		log.info("Guard_RESTApp started");
	}
}
