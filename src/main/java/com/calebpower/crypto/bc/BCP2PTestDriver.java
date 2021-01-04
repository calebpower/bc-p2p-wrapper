package com.calebpower.crypto.bc;

import org.bouncycastle.util.encoders.Base64;

public class BCP2PTestDriver {
  
  public static void main(String[] args) {
    System.out.println("Hello, world!");
    
    try {
      String plaintext = "This is my really cool plaintext.";
      // String key = "01234567890123456789012345678901"; // needs to be 256 bits
      //String iv = "1234567891234567"; // 128 bits
      
      SymmetricEngine symmetricEngine = new SymmetricEngine();
      String key = symmetricEngine.genKey();
      
      System.out.printf("Plaintext: %1$s\nKey: %2$s\n", plaintext, key);
      
      //SymmetricEngine symmetricEngine = new SymmetricEngine(key, iv);
      //SymmetricEngine symmetricEngine2 = new SymmetricEngine(key, iv);
      
      System.out.println("Key size = " + (Base64.decode(key).length * 8));
      
      String ciphertext = null;
      System.out.printf("Encrypted: %1$s\n", ciphertext = symmetricEngine.encrypt(plaintext, key));
      System.out.printf("Decrypted: %1$s\n", symmetricEngine.decrypt(ciphertext, key));
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
}
