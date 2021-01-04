package com.calebpower.crypto.bc;

public class BCP2PTestDriver {
  
  public static void main(String[] args) {
    System.out.println("Hello, world!");
    
    try {
      String plaintext = "This is my really cool plaintext.";
      String key = "Olmy9iqs1LwWblwe";
      String iv = "1234567891234567";
      
      System.out.printf("Plaintext: %1$s\nKey: %2$s\nIV: %3$s\n", plaintext, key, iv);
      
      SymmetricEngine symmetricEngine = new SymmetricEngine(key, iv);
      
      String ciphertext = null;
      System.out.printf("Encrypted: %1$s\n", ciphertext = symmetricEngine.encrypt(plaintext));
      System.out.printf("Decrypted: %1$s\n", symmetricEngine.decrypt(ciphertext));
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
}
