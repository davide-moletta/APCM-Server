package it.unitn.APCM.ACME.Guard;

import javax.crypto.SecretKey;

import it.unitn.APCM.ACME.DBManager.SSS.Shamir;
import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

public class test {
    static SecretKey masterKey;

    public static void main(String[] args) {
        Shamir sh = new Shamir();
        masterKey = sh.getMasterSecret();

        System.out.print("Master key: "); 
        String m = new String(masterKey.getEncoded());
        System.out.println(m);
        System.out.println(masterKey.getAlgorithm());

        ArrayList<SecretKey> keys = new ArrayList<SecretKey>();

        for(int i = 0; i < 50; i++) {
            keys.add((new CryptographyPrimitive()).getSymmetricKey());
        }

        for(int i = 0; i < 50; i++) {
            System.out.print("Original key: "); 
            String pre = new String(keys.get(i).getEncoded());
            System.out.println(pre);
            byte[] encKey = (new CryptographyPrimitive()).encrypt(keys.get(i).getEncoded(), masterKey);
            System.out.println("Encrypted key: "); 
            m = new String(encKey);
            System.out.println(m);
            byte[] decKey = (new CryptographyPrimitive()).decrypt(encKey, masterKey);
            System.out.println("Decrypted key: "); 
            String dec = new String(decKey);
            System.out.println(dec);
            if(pre.equals(dec)){
                System.out.println("OK");
            } else {
                System.out.println("NO");
            }
            System.out.println("Loop end\n\n");
        }
    }
}
