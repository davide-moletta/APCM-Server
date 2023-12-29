package it.unitn.APCM.ACME.Guard;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.sql.Connection;

@RestController
public class Guard_RESTInterface {
	// Connection statically instantiated
	private final Connection conn = Guard_Connection.getDbconn();
	private String dbServer_url = "http://localhost:8091/files?";

	@RequestMapping(path = "/file", method = RequestMethod.GET)
	public String login(@RequestParam String user, @RequestParam String pwd, @RequestParam String path) {

		// DB_Connection.connect("users");

		// final String query = "SELECT * FROM USERS WHERE user = ? AND pwd = ?";

		// PreparedStatement ps = connection.PreparedStatement(query);

		// //check values

		// ps.setString(0, user);
		// ps.setString(1, pwd);

		// ResultSet result = ps.executeQuery();

		if (!user.equals("davide") || !pwd.equals("ciao"))
			return "wrong credentials";

		String[] groups = new String[2];
		groups[0] = "admin";
		groups[1] = "student";

		String tmpUrl = dbServer_url + "user=" + user + "&groups=" + groups[0] + "&path=" + path;

		RestTemplate restTemplate = new RestTemplate();

		ResponseEntity<String> response = restTemplate.getForEntity(tmpUrl, String.class);

		if (response.getStatusCode() == HttpStatus.OK) {
			String responseBody = response.getBody();
			return responseBody;
		} else {
			return "file does not exists";
		}
	}
}
