package com.calebpower.crypto.bc;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;

public class SymmetricEngine {
  
  private static final int BLOCK_SIZE = 16;
  private static final int KEY_SIZE = 32;
  private static final String CHARSET = "UTF-8";
  
  private PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
      new CBCBlockCipher(new AESEngine()),
      new PKCS7Padding());
  // private ParametersWithIV keyParamWithIV = null;
  
  /*
  public SymmetricEngine(String key, String iv) throws Exception {
    byte[] keyBytes = key.getBytes("UTF-8");
    byte[] saltBytes = new byte[0];
    // PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
    // generator.init(keyBytes, saltBytes, 4096);
    // keyParamWithIV = (ParametersWithIV)generator.generateDerivedParameters(256, 128);
    // byte[] derivedKey = ((KeyParameter)generator.generateDerivedParameters(256, 128)).getKey();
    
    // keyParamWithIV = new ParametersWithIV(new KeyParameter(key.getBytes("UTF-8")), iv.getBytes("UTF-8"), 0, 16);
  }
  */
  
  public String genKey() throws NoSuchAlgorithmException {
    byte[] bytes = new byte[KEY_SIZE];
    SecureRandom.getInstanceStrong().nextBytes(bytes);
    return new String(Base64.encode(bytes));
  }
  
  public String encrypt(String plaintext, String key) throws Exception {
    byte[] iv = new byte[BLOCK_SIZE];
    SecureRandom.getInstanceStrong().nextBytes(iv);
    ParametersWithIV keyParamWithIV = new ParametersWithIV(new KeyParameter(Base64.decode(key)), iv);
    
    cipher.init(true, keyParamWithIV);
    byte[] plaintextBytes = plaintext.getBytes(CHARSET);
    byte[] ciphertextBytes = new byte[cipher.getOutputSize(plaintextBytes.length) + BLOCK_SIZE];
    
    printBytes(ciphertextBytes);
    
    for(int i = 0; i < BLOCK_SIZE; i++) ciphertextBytes[i] = iv[i];
    
    printBytes(ciphertextBytes);
    
    cipher.doFinal(ciphertextBytes,
        cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertextBytes, BLOCK_SIZE) + BLOCK_SIZE);
    
    printBytes(ciphertextBytes);
    
    return new String(Base64.encode(ciphertextBytes));
  }
  
  public String decrypt(String ciphertext, String key) throws Exception {
    byte[] ciphertextBytes = Base64.decode(ciphertext);

    ParametersWithIV keyParamWithIV = new ParametersWithIV(new KeyParameter(Base64.decode(key)), ciphertextBytes, 0, BLOCK_SIZE);
    cipher.init(false, keyParamWithIV);
    
    byte[] plaintextBytes = new byte[cipher.getOutputSize(ciphertextBytes.length - BLOCK_SIZE)];
    cipher.doFinal(plaintextBytes,
        cipher.processBytes(ciphertextBytes, BLOCK_SIZE, ciphertextBytes.length - BLOCK_SIZE, plaintextBytes, 0));
    return new String(plaintextBytes, CHARSET);
  }
  
  public void printBytes(byte[] bytes) {
    for(int i = 0; i < bytes.length; i++) {
      System.out.printf("%02X ", bytes[i]);
      if((i + 1) % 16 == 0) System.out.println();
    }
    System.out.println();
  }
  
}
