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

/**
 * Encrypts and decrypts messages with a symmetric key.
 * Generates said key, and the appropriate IV.
 * 
 * - Algorithm: AES 256
 * - Block Cipher: CBC
 * - Padding: PKCS7
 * 
 * @author Caleb L. Power
 */
public class SymmetricEngine {
  
  private static final int BLOCK_SIZE = 16; // 16 bytes = 128 bits
  private static final int KEY_SIZE = 32; // 32 bytes = 256 bits
  private static final String CHARSET = "UTF-8";
  
  private PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
      new CBCBlockCipher(new AESEngine()),
      new PKCS7Padding());
  
  /**
   * Securely generates a pseudorandom 256-bit key.
   * 
   * @return a Base64-encoded 256-bit key
   * @throws NoSuchAlgorithmException thrown if the SecureRandom strong instance can't be found
   */
  public String genKey() throws NoSuchAlgorithmException {
    byte[] bytes = new byte[KEY_SIZE];
    SecureRandom.getInstanceStrong().nextBytes(bytes);
    return new String(Base64.encode(bytes));
  }
  
  /**
   * Encrypts plaintext using a 256-bit key.
   * 
   * @param plaintext the plaintext
   * @param key the 256-bit key
   * @return Base64-encoded ciphertext preceded by the IV
   * @throws Exception if something went wrong
   */
  public String encrypt(String plaintext, String key) throws Exception {
    byte[] keyBytes = Base64.decode(key); // decode
    
    // must be exactly 256 bits; consider PBKDF2 (PKCS5S2) for key expansion algorithms if keys aren't auto-generated
    if(keyBytes.length != KEY_SIZE) throw new Exception("Bad key length.");
    
    byte[] iv = new byte[BLOCK_SIZE];
    SecureRandom.getInstanceStrong().nextBytes(iv); // generate a random initial vector
    
    ParametersWithIV keyParamWithIV = new ParametersWithIV(new KeyParameter(Base64.decode(key)), iv);
    
    cipher.init(true, keyParamWithIV);
    byte[] plaintextBytes = plaintext.getBytes(CHARSET);
    
    // the ciphertext is going to have the IV prepended to it
    byte[] ciphertextBytes = new byte[cipher.getOutputSize(plaintextBytes.length) + BLOCK_SIZE];
    
    BCP2PTestDriver.printBytes(ciphertextBytes); // XXX prints the blank array for confirmation
    
    for(int i = 0; i < BLOCK_SIZE; i++) ciphertextBytes[i] = iv[i];
    
    BCP2PTestDriver.printBytes(ciphertextBytes); // XXX prints the array with the only an IV
    
    cipher.doFinal(ciphertextBytes,
        cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertextBytes, BLOCK_SIZE) + BLOCK_SIZE);
    
    BCP2PTestDriver.printBytes(ciphertextBytes); // XXX prints the array with the appended encryption
    
    return new String(Base64.encode(ciphertextBytes)); // returns Base64-encoded ciphertext
  }
  
  /**
   * Decrypts ciphertext using a 256-bit key.
   * 
   * @param ciphertext the ciphertext, with a 128-bit IV prepended to it
   * @param key the 256-bit key
   * @return the plaintext
   * @throws Exception if something went wrong
   */
  public String decrypt(String ciphertext, String key) throws Exception {
    byte[] ciphertextBytes = Base64.decode(ciphertext);

    ParametersWithIV keyParamWithIV = new ParametersWithIV(new KeyParameter(Base64.decode(key)), ciphertextBytes, 0, BLOCK_SIZE);
    cipher.init(false, keyParamWithIV);
    
    byte[] plaintextBytes = new byte[cipher.getOutputSize(ciphertextBytes.length - BLOCK_SIZE)];
    cipher.doFinal(plaintextBytes,
        cipher.processBytes(ciphertextBytes, BLOCK_SIZE, ciphertextBytes.length - BLOCK_SIZE, plaintextBytes, 0));
    return new String(plaintextBytes, CHARSET);
  }
  
}
