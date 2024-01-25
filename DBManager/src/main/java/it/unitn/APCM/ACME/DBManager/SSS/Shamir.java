package it.unitn.APCM.ACME.DBManager.SSS;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.mitre.secretsharing.Part;
import org.mitre.secretsharing.Secrets;
import org.mitre.secretsharing.codec.PartFormats;

import it.unitn.APCM.ACME.ServerCommon.CryptographyPrimitive;

public class Shamir {
    public static void main(String[] args) {
        SecretKey cipherKey = (new CryptographyPrimitive()).getSymmetricKey();
		System.out.println(new String(cipherKey.getEncoded()));
        
        Part[] parts = Secrets.split(cipherKey.getEncoded(), 5, 3, new SecureRandom());
        for(Part p : parts){
            System.out.println(PartFormats.currentStringFormat().format(p));
        }
        byte[] key = Secrets.join(parts);
        System.out.println(new String(key));
       
        if(Arrays.equals(key, cipherKey.getEncoded())){
            System.out.println("Equal");
        } else {
            System.out.println("Different");
        }
    }
    
}
