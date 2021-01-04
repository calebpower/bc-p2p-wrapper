package com.calebpower.crypto.bc;

import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;

/**
 * Test driver for various Bouncy Castle algorithms, the purpose of which is to
 * serve as a proof-of-concept for automatic generation of various keys and the
 * sharing of per-document symmetric keys.
 * 
 * @author Caleb L. Power
 */
public class BCP2PTestDriver {
  
  /**
   * Entry points.
   * 
   * @param args program arguments
   */
  public static void main(String... args) {
    System.out.println("Hello, world!");
    // Security.addProvider(new BouncyCastleProvider());
    
    String plaintext = "This is my really cool plaintext.";
    
    try { // This tests the symmetric engine
      SymmetricEngine symmetricEngine = new SymmetricEngine();
      String key = symmetricEngine.genKey();
      System.out.printf("Plaintext: %1$s\nKey: %2$s\n", plaintext, key);
      System.out.println("Key size = " + (Base64.decode(key).length * 8));
      
      String ciphertext = null;
      System.out.printf("Encrypted: %1$s\n", ciphertext = symmetricEngine.encrypt(plaintext, key));
      System.out.printf("Decrypted: %1$s\n", symmetricEngine.decrypt(ciphertext, key));
    } catch(Exception e) {
      e.printStackTrace();
    }
    
    try { // This tests the asymmetric engine
      AsymmetricEngine asymmetricEngine = new AsymmetricEngine();
      KeyPair alice = asymmetricEngine.genKey();
      String alicePriv = new String(Base64.encode(alice.getPrivate().getEncoded()));
      
      //PrivateKeyFactory.createKey(Base64.decode(alicePriv));
      //ECPrivateKeySpec keySpec = new ECPrivate
      
      //ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp384r1");
      //ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(1, Base64.decode(alicePriv)), spec);
      
      try {
        new X509EncodedKeySpec(Base64.decode(alicePriv));
        System.out.println("X509 works");
      } catch(Exception e) {
        System.out.println("X509 doesn't work");
      }
      
      try {
        new PKCS8EncodedKeySpec(Base64.decode(alicePriv));
        System.out.println("PKCS8 works");
      } catch(Exception e) {
        System.out.println("PKCS8 doesn't work");
      }
      
      System.out.println(alicePriv);
      KeyPair bob = asymmetricEngine.genKey();
      
      
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Utility to print a byte array in hex;
   * 
   * @param bytes the byte array
   */
  public static void printBytes(byte[] bytes) {
    for(int i = 0; i < bytes.length; i++) {
      System.out.printf("%02X ", bytes[i]);
      if((i + 1) % 16 == 0) System.out.println();
    }
    System.out.println();
  }
}
