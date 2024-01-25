package it.unitn.APCM.ACME.DBManager.SSS;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.mitre.secretsharing.Part;
import org.mitre.secretsharing.Secrets;
import org.mitre.secretsharing.codec.PartFormats;

import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

public class Shamir {
    public static void main(String[] args) {
        generateShamir();
        generateEffectiveKey(args);
    } 

    private static void generateEffectiveKey(String[] args){
        Part[] parts = new Part[args.length];

        for(int i = 0; i < args.length; i++){
            parts[i] = PartFormats.parse(args[i]);
        }
        byte[] keyByte = Secrets.join(parts);
		SecretKey masterKey =  new SecretKeySpec(keyByte, 0, keyByte.length, "AES");

        SecretKey effectiveKey = (new CryptographyPrimitive()).getSymmetricKey();

        (new CryptographyPrimitive()).encrypt(effectiveKey.getEncoded(), masterKey);
    }

    private static void generateShamir(){
        SecretKey cipherKey = (new CryptographyPrimitive()).getSymmetricKey();
        
        Part[] parts = Secrets.split(cipherKey.getEncoded(), 5, 3, new SecureRandom());
        byte[] key = Secrets.join(parts);
        
        if(Arrays.equals(key, cipherKey.getEncoded())){
            System.out.println("Equal");
        } else {
            System.out.println("Different");
        }
    }
}
