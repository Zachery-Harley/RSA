package com.zacheryharley.java.secureLan.keys;

import java.math.BigInteger;
import java.util.Random;

import com.zacheryharley.java.secureLan.Main;

public class KeyGen {
   
   /**
    * The prime numbers used to generate the key to encrypt and decrypt data
    */
   private BigInteger primeA;
   private BigInteger primeB;
   
   private BigInteger n; // primeA * primeB //Part of the public key
   private BigInteger m; // lcm(primeA - 1, primeB -1)
   private BigInteger r; // Part of the public key
   private BigInteger d; // The private decrytion number
   private int bitLength = 1024;
   private Random random = new Random();
   
   
   public KeyGen(int bitCount){
      this.bitLength = bitCount;
   }
   
   ////////////////////Public Methods\\\\\\\\\\\\\\\\\\\\
   
   
   
   
   public boolean generateKeys(){
      
      primeA = BigInteger.probablePrime(bitLength, random);
      primeB = BigInteger.probablePrime(bitLength, random);
      
      
      //Calc n
      n = primeA.multiply(primeB);
      
      //Calc m
      BigInteger tPrimeA = primeA.subtract(BigInteger.ONE);
      BigInteger tPrimeB = primeB.subtract(BigInteger.ONE);
      m = tPrimeA.multiply(tPrimeB);
      
      //Calculate R
      r = BigInteger.probablePrime(bitLength / 2, random);
      //r = new BigInteger("3");
      
      
      while (m.gcd(r).compareTo(BigInteger.ONE) > 0 && r.compareTo(m) < 0)

      {

          r.add(BigInteger.ONE);

      }

      d = r.modInverse(m);

      return true;
   }
   
   public BigInteger getPrivA(){
      return d;
   }
   
   public BigInteger getPrivB(){
      return n;
   }
   
   public BigInteger getPubA(){
      return r;
   }
   
   public BigInteger getPubB(){
      return n;
   }
   
   public byte[] encrypt(byte[] message){
      BigInteger t = new BigInteger(message).modPow(r, n);
      return t.toByteArray();
   }
   
   
   public byte[] decrypt(byte[] message){
      BigInteger t = new BigInteger(message).modPow(d, n);
      return t.toByteArray();
   }
   
   
   public String byteToString(byte[] message){
      String output = "";
      for(byte b : message){
         output += Byte.toString(b);
      }
      return output;
   }
   ////////////////////Private Methods\\\\\\\\\\\\\\\\\\\\


}
