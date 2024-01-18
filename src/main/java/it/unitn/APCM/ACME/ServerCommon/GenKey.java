package it.unitn.APCM.ACME.ServerCommon;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class GenKey {
    // encryption algorithm
	// CHECK TYPE OF ENCRYPTION ALGORITHM
	static final String cipherString = "ChaCha20";
	// length of key in bytes
	static final int keyByteLen = 32;
	// IV length
	static final int IVLEN = 12;

    public String getFixedSymmetricKey(){
        SecretKey cipherKey = null;
        
		// if no valid data read from file, create new
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance(cipherString);
			// specify key length in bits
			keygen.init(keyByteLen * 8);
			cipherKey = keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

        if (cipherKey != null) {
            return new String(cipherKey.getEncoded());
        } else {
            return null;
        }
    }

}
