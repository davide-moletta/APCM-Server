package it.unitn.APCM.ACME.DBManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import it.unitn.APCM.ACME.DBManager.SSS.Shamir;

import java.util.HashMap;

import javax.crypto.SecretKey;

@SpringBootApplication
public class DB_RESTApp {
	private static final Logger log = LoggerFactory.getLogger(DB_RESTApp.class);
	protected static SecretKey masterKey;

	// encryption algorithm
	// CHECK TYPE OF ENCRYPTION ALGORITHM
	static final String cipherString = "ChaCha20";
	// IV length
	static final int IVLEN = 12;

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(DB_RESTApp.class);
		HashMap<String, Object> properties = new HashMap<String, Object>(2);
		properties.put("server.port", "8091");
		properties.put("spring.application.name", "DBManager_RESTApp");
		app.setDefaultProperties(properties);
		app.run(args);
		Shamir sh = new Shamir();
		masterKey = sh.getMasterSecret();
		log.info("DB_RESTApp started");
		//changeValue();
	}
	/* 
	private static final Connection conn = DB_Connection.getDbconn();

	// Test to set the encryption key of the file (not encrypted with master key)
	private static void changeValue(){
		String selectQuery = "SELECT encryption_key FROM Files WHERE 1 = 1";
		PreparedStatement preparedStatement;
		String key = "";
		try {
			preparedStatement = conn.prepareStatement(selectQuery);
			ResultSet rs = preparedStatement.executeQuery();

			while (rs.next()) {
				key = rs.getString("encryption_key");
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		
		System.out.println(key);

		
		String encKey = new String(encrypt(key.getBytes()));
		String updateQuery = "UPDATE Files SET encryption_key = ? WHERE 1 = 1";
		PreparedStatement prepStatement;
		try {
			prepStatement = conn.prepareStatement(updateQuery);
			prepStatement.setString(1, encKey);
			int rs = prepStatement.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}

	// encrypt key
	private static byte[] encrypt(byte[] keyToEnc) {
		// check that there is some data to encrypt
		if (keyToEnc.length == 0) {
			log.error("No key to encrypt");
			return null;
		}
		try {
			// Create the cipher
			Cipher cipher = Cipher.getInstance(cipherString);
			// Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, DB_RESTApp.masterKey);

			// Retrieve the parameters used during encryption
			// they will be needed for decryption
			byte[] iv = cipher.getIV();

			// Encrypt the input data
			byte[] ciphertext = cipher.doFinal(keyToEnc);

			// set output
			byte[] encrytedKey = new byte[iv.length + ciphertext.length];
			// first part is the IV
			System.arraycopy(iv, 0, encrytedKey, 0, IVLEN);
			// second part is the ciphertext
			System.arraycopy(ciphertext, 0, encrytedKey, IVLEN, ciphertext.length);

			log.trace("Encrypted key");
			return encrytedKey;

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			log.error("Encryption failed: " + e);
			return null;
		}
	}*/
}
