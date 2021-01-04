package com.calebpower.crypto.bc;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
    Security.addProvider(new BouncyCastleProvider());
    
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
      String alicePub = new String(Base64.encode(alice.getPublic().getEncoded()));
      KeyPair bob = asymmetricEngine.genKey();
      String bobPriv = new String(Base64.encode(bob.getPrivate().getEncoded()));
      String bobPub = new String(Base64.encode(bob.getPublic().getEncoded()));
      
      PrivateKey aliceRegenPriv = asymmetricEngine.regenPrivkey(alicePriv);
      PublicKey aliceRegenPub = asymmetricEngine.regenPubkey(alicePub);
      PrivateKey bobRegenPriv = asymmetricEngine.regenPrivkey(bobPriv);
      PublicKey bobRegenPub = asymmetricEngine.regenPubkey(bobPub);
      
      String aliceOrigEncryptBobOrig = asymmetricEngine.encrypt(plaintext, alice.getPrivate(), bob.getPublic());
      String aliceRegenEncryptBobRegen = asymmetricEngine.encrypt(plaintext, aliceRegenPriv, bobRegenPub);
      String bobOrigEncryptAliceOrig = asymmetricEngine.encrypt(plaintext, bob.getPrivate(), alice.getPublic());
      String bobRegenEncryptAliceRegen = asymmetricEngine.encrypt(plaintext, bobRegenPriv, aliceRegenPub);
      
      System.out.println("Alice privkey #1: " + new String(Base64.encode(alice.getPrivate().getEncoded())));
      printBytes(alice.getPrivate().getEncoded());
      
      System.out.println("Alice privkey #2: " + new String(Base64.encode(aliceRegenPriv.getEncoded())));
      printBytes(aliceRegenPriv.getEncoded());
      
      System.out.println("Alice pubkey #1: " + new String(Base64.encode(alice.getPublic().getEncoded())));
      printBytes(alice.getPublic().getEncoded());
      
      System.out.println("Alice pubkey #2: " + new String(Base64.encode(aliceRegenPub.getEncoded())));
      printBytes(aliceRegenPub.getEncoded());
      
      System.out.println("Bob privkey #1: " + new String(Base64.encode(bob.getPrivate().getEncoded())));
      printBytes(bob.getPrivate().getEncoded());
      
      System.out.println("Bob privkey #2: " + new String(Base64.encode(bobRegenPriv.getEncoded())));
      printBytes(bobRegenPriv.getEncoded());
      
      System.out.println("Bob pubkey #1: " + new String(Base64.encode(bob.getPublic().getEncoded())));
      printBytes(bob.getPublic().getEncoded());
      
      System.out.println("Bob pubkey #2: " + new String(Base64.encode(bobRegenPub.getEncoded())));
      printBytes(bobRegenPub.getEncoded());
      
      System.out.println("Alice -> Bob #1: " + aliceOrigEncryptBobOrig);
      System.out.println("Alice -> Bob #2: " + aliceRegenEncryptBobRegen);
      System.out.println("Bob -> Alice #1: " + bobOrigEncryptAliceOrig);
      System.out.println("Bob -> Alice #2: " + bobRegenEncryptAliceRegen);
      
      String signedByAlice = asymmetricEngine.sign(plaintext, aliceRegenPriv);
      System.out.println("signed by alice = " + signedByAlice);
      String signedByBob = asymmetricEngine.sign(plaintext, bobRegenPriv);
      System.out.println("signed by bob = " + signedByBob);
      
      System.out.println("alice signed by alice? " + asymmetricEngine.verify(plaintext, signedByAlice, aliceRegenPub));
      System.out.println("alice signed by bob? " + asymmetricEngine.verify(plaintext, signedByAlice, bobRegenPub));
      System.out.println("bob signed by bob? " + asymmetricEngine.verify(plaintext, signedByBob, bobRegenPub));
      System.out.println("bob signed by alice? " + asymmetricEngine.verify(plaintext, signedByBob, aliceRegenPub));
      
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
    int i;
    for(i = 0; i < bytes.length; i++) {
      System.out.printf("%02X ", bytes[i]);
      if((i + 1) % 16 == 0) System.out.println();
    }
    if((i + 1) % 16 != 0) System.out.println();
    System.out.println();
  }
}
