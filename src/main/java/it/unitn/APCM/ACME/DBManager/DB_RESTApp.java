package it.unitn.APCM.ACME.DBManager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class DB_RESTApp {
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		HashMap properties = new HashMap(2);
		properties.put("server.port", "8091");
		properties.put("spring.application.name", "DBManager_RESTApp");
		app.setDefaultProperties(properties);
		app.run(args);
	}
}