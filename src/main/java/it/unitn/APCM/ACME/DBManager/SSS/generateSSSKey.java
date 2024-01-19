package it.unitn.APCM.ACME.DBManager.SSS;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class generateSSSKey {
    // CHECK TYPE OF ENCRYPTION ALGORITHM
	static final String cipherString = "AES";
    static final String transormation = "AES/GCM/NOPadding";
	// length of key in bytes
	static final int keyByteLen = 32;
	// IV length
	static final int IVLEN = 12;


    public static void main(String[] args) {
        getFixedSymmetricKey();
        setKeys();
    }

    private static SecretKey getFixedSymmetricKey(){
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
		
		System.out.println("new key generated: ");
		System.out.println(new String(cipherKey.getEncoded()));

		try
    	{
            PrintWriter outSeed = new PrintWriter("key.txt");
			for (byte theByte : cipherKey.getEncoded())
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.close();
		}
		catch (IOException e){
			System.out.println("IOException : " + e);
		}

        return cipherKey;
    }
	
	private static void setKeys(){
		byte[] key = null;
		try {
			String content = new String(Files.readAllBytes(Paths.get("key.txt")));
			String[] seedString = (content.split(","));
			key = new byte[seedString.length];
			int i = 0;
			for(String s: seedString){
				key[i] = (byte)(Integer.parseInt(s));
				i++;
			}
			System.out.println(new String(key));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		SecureRandom secRandom = new SecureRandom();
		byte[] seed = secRandom.generateSeed(256);
		secRandom.setSeed(seed);
		System.out.println(seed);

		try
    	{
            PrintWriter outSeed = new PrintWriter("seed.txt");
			for (byte theByte : seed)
			{
				System.out.println(Integer.toString(theByte));
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.close();
		}
		catch (IOException e){
			System.out.println("IOException : " + e);
		}

		Shamir sc = new Shamir(secRandom, 5, 3); 
		//return null;
		
	    Map<Integer, byte[]> keySplitted = sc.split(key);
		String v;
		for(Map.Entry<Integer, byte[]> entry : keySplitted.entrySet()){
			System.out.println("Key= " + entry.getKey() + ", Value = " + entry.getValue());
		}
		// return null;
		 	
			 
		try
    	{
            PrintWriter outSeed = new PrintWriter("keys.txt");
			for (byte theByte : keySplitted.get(1))
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.print(";");
			for (byte theByte : keySplitted.get(2))
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.print(";");
			for (byte theByte : keySplitted.get(3))
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.print(";");
			for (byte theByte : keySplitted.get(4))
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.print(";");
			for (byte theByte : keySplitted.get(5))
			{
			 	outSeed.print(Integer.toString(theByte) + ",");
			}
			outSeed.close();
		}
		catch (IOException e){
			System.out.println("IOException : " + e);
		}
	}

    
}
