package com.zacheryharley.java.secureLan.keys;

import java.math.BigInteger;

import com.zacheryharley.java.secureLan.Main;

public class KeyPair {

	private KeyGen keyGenerator = null;
	
	/**
	 * Create a new key pair and generate a private key of the
	 * provided strength.
	 * 
	 * @param strength  
	 */
	public KeyPair(int strength) {
		if(strength > 10){
			keyGenerator = new KeyGen(strength);
			//Generate the key
			keyGenerator.generateKeys();
			this.setPriv(keyGenerator.getPrivA(), keyGenerator.getPrivB());
		} else {
			//TODO add exceptions
		}
	}
	
	/**
	 * Create a new key pair using an already created keygen. The keys will be loaded
	 * from the keygen and not generated again.
	 * @param sourceGenerator The KeyGen to load the private key from
	 */
	public KeyPair(KeyGen sourceGenerator){
		keyGenerator = sourceGenerator;
		this.setPriv(keyGenerator.getPrivA(), keyGenerator.getPrivB());
	}
	
   /**
    * The public key of the other party
    */
   private BigInteger pubA;
   private BigInteger pubB;
   
   /**
    * Your private key
    */
   private BigInteger privA;
   private BigInteger privB;
   
   /**
    * Set the public key values, these are used to encrypt
    * @param a The first part of the public key
    * @param b The second part of the public key
    * 
    * @see #encrypt(byte[])S
    */
   public void setPub(BigInteger a, BigInteger b){
      this.pubA = a;
      this.pubB = b;
   }
   
   /**
    * Set the private key values, these will be used to decrypt;
    * @param a The first part the private key
    * @param b The second part of the private key
    * 
    * @see #decrypt(byte[])
    */
   public void setPriv(BigInteger a, BigInteger b){
      this.privA = a;
      this.privB = b;
   }
    
   /**
    * Encrypt the given byte array using the given public key in this key pair.
    * @param message The byte array to encrypted
    * @return The encrypted byte array
    */
   public byte[] encrypt(byte[] message){
      BigInteger t = new BigInteger(message).modPow(pubA, pubB);
      return t.toByteArray();
   }
   
   /**
    * Decrypt the given byte array using the private key in this key pair.
    * @param message The byte array to decrypt
    * @return The decrypted byte array
    */
   public byte[] decrypt(byte[] message){
      BigInteger t = new BigInteger(message).modPow(privA, privB);
      return t.toByteArray();
   }
   
   /**
    * Convert a byte array to a string. This expects the input byte array to be
    * alpha numerical. 
    * @param message The byte array to convert to a string
    * @return The decoded string
    */
   public static String byteToString(byte[] message){
      String output = "";
      for(byte b : message){
         output += Byte.toString(b);
      }
      return output;
   }
   
   /**
    * Get the keygen used to generate the private keys
    * @return KeyGen
    */
   public KeyGen getKeyGen(){
	   return this.keyGenerator;
   }
   
   /**
    * Return a string showing both the public and private key.
    * This should not be sent across the network, instead is
    * for debug purposes only. 
    */
   public String toString(){
      String output = "Key Pair: \n"
            + "Private key A = " + privA.toString();
      output += "\nPrivate key B = " + privB.toString();
      output += "\nPublic key A = " + pubA.toString();
      output += "\nPublic key B = " + pubB.toString();
      return output;
   }
   
   
}
