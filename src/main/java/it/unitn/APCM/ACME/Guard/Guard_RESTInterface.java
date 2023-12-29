package it.unitn.APCM.ACME.Guard;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
public class Guard_RESTInterface {
	@GetMapping("/users")
	public String get_files(@RequestParam(value = "name", defaultValue = "World") String name) {
		return LocalDateTime.now().toString();
	}
}