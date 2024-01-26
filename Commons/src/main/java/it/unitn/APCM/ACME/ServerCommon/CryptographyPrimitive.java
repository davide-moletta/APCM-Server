package it.unitn.APCM.ACME.ServerCommon;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The type Cryptography primitive.
 */
public class CryptographyPrimitive {

    /**
     * The Algorithm.
     */
    static final String algorithm = "AES";
    /**
     * The Transformation.
     */
    static final String transformation = "AES/GCM/NoPadding";
    /**
     * The Key byte len.
     */
    static final int keyByteLen = 32;
    /**
     * The Ivlen.
     */
    static final int IVLEN = 12;

    /**
     * Gets hash.
     *
     * @param hash the hash
     * @return the hash
     */
// Function that returns the hash of a byte array
    public String getHash(byte[] hash) {
        try {
            // Instantiate the SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            // Compute the hash
            byte[] bytes = md.digest(hash);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * Gets symmetric key.
     *
     * @return the symmetric key
     */
// Function to generate a random symmetric key
    public SecretKey getSymmetricKey() {
        SecretKey cipherKey = null;

        // if no valid data read from file, create new
        KeyGenerator keygen;
        try {
            // instantiate key generator with the specified algorithm
            keygen = KeyGenerator.getInstance(algorithm);
            // specify key length in bits
            keygen.init(keyByteLen * 8);
            // generate the key
            cipherKey = keygen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return cipherKey;
    }

    /**
     * Encrypt byte [ ].
     *
     * @param textToEnc the text to enc
     * @param key       the key
     * @return the byte [ ]
     */
// Function to encrypt a byte array with a symmetric key
    public byte[] encrypt(byte[] textToEnc, SecretKey key) {
        // check that there is some data to encrypt
        if (textToEnc.length == 0) {
            return null;
        }
        try {
            // Create the cipher
            Cipher cipher = Cipher.getInstance(transformation);

            byte[] iv = new byte[IVLEN];
            (new SecureRandom()).nextBytes(iv);
            GCMParameterSpec spec = new GCMParameterSpec(IVLEN * java.lang.Byte.SIZE, iv);
            // Initialize the cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            // Encrypt the input data
            byte[] ciphertext = cipher.doFinal(textToEnc);

            // set output
            byte[] encrytedText = new byte[iv.length + ciphertext.length];
            // first part is the IV
            System.arraycopy(iv, 0, encrytedText, 0, IVLEN);
            // second part is the ciphertext
            System.arraycopy(ciphertext, 0, encrytedText, IVLEN, ciphertext.length);

            return encrytedText;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            return null;
        }
    }

    /**
     * Decrypt byte [ ].
     *
     * @param encText the enc text
     * @param key     the key
     * @return the byte [ ]
     */
// Function to decrypt a byte array with a symmetric key
    public byte[] decrypt(byte[] encText, SecretKey key) {
        // check that there is some data to decrypt
        if (encText.length == 0) {
            return null;
        }
        try {
            byte[] decText;
            // Create the cipher
            Cipher cipher = Cipher.getInstance(transformation);
            // Retrieve the parameters used during encryption to properly
            // initialize the cipher for decryption
            byte[] iv = new byte[IVLEN];
            byte[] ciphertext = new byte[encText.length - IVLEN];
            // first part is the IV
            System.arraycopy(encText, 0, iv, 0, IVLEN);
            // second part is the ciphertext
            System.arraycopy(encText, IVLEN, ciphertext, 0, ciphertext.length);
            // initialize parameters
            GCMParameterSpec spec = new GCMParameterSpec(IVLEN * java.lang.Byte.SIZE, iv);
            // Initialize cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            // Decrypt the input data
            decText = cipher.doFinal(ciphertext);

            return decText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            return null;
        }
    }
}
