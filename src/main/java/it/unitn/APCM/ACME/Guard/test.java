package it.unitn.APCM.ACME.Guard;

import javax.crypto.SecretKey;

import it.unitn.APCM.ACME.DBManager.SSS.Shamir;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;

public class test {

    static final String cipherString = "ChaCha20";
    static final int keyByteLen = 32;
    static final int IVLEN = 12;
    static SecretKey masterKey;

    public static void main(String[] args) {
        Shamir sh = new Shamir();
        masterKey = sh.getMasterSecret();

        System.out.println("Master key: " + masterKey);

        ArrayList<SecretKey> keys = new ArrayList<SecretKey>();

        for(int i = 0; i < 50; i++) {
            keys.add(getSymmetricKey());
        }

        for(int i = 0; i < 50; i++) {
            System.out.println("Original key: " + new String(keys.get(i).getEncoded()));
            byte[] encKey = encrypt(keys.get(i).getEncoded());
            System.out.println("Encrypted key: " + new String(encKey));
            byte[] decKey = decrypt(encKey);
            System.out.println("Decrypted key: " + new String(decKey));
            System.out.println("Loop end");
        }
    }

    private static SecretKey getSymmetricKey() {
        SecretKey cipherKey = null;

        // if no valid data read from file, create new
        KeyGenerator keygen;
        try {
            keygen = KeyGenerator.getInstance(cipherString);
            // specify key length in bits
            keygen.init(keyByteLen * 8);
            cipherKey = keygen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return cipherKey;
    }

    // encrypt key
    private static byte[] encrypt(byte[] keyToEnc) {
        // check that there is some data to encrypt
        if (keyToEnc.length == 0) {
            return null;
        }
        try {
            // Create the cipher
            Cipher cipher = Cipher.getInstance(cipherString);
            // Initialize the cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, masterKey);

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

            return encrytedKey;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            return null;
        }
    }

    // decrypt key
    private static byte[] decrypt(byte[] encKey) {
        // check that there is some data to decrypt
        if (encKey.length == 0) {
            return null;
        }
        try {
            byte[] decKey;
            // Create the cipher
            Cipher cipher = Cipher.getInstance(cipherString);
            // Retrieve the parameters used during encryption to properly
            // initialize the cipher for decryption
            byte[] iv = new byte[IVLEN];
            byte[] ciphertext = new byte[encKey.length - IVLEN];
            // first part is the IV
            System.arraycopy(encKey, 0, iv, 0, IVLEN);
            // second part is the ciphertext
            System.arraycopy(encKey, IVLEN, ciphertext, 0, ciphertext.length);
            // initialize parameters
            // !!! this is specific for ChaCha20
            AlgorithmParameterSpec chachaSpec = new ChaCha20ParameterSpec(iv, 1);
            // Initialize cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, masterKey, chachaSpec);
            // Decrypt the input data
            decKey = cipher.doFinal(ciphertext);

            return decKey;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            return null;
        }
    }

}
