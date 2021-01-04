package com.calebpower.crypto.bc;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;

public class SymmetricEngine {
  
  private PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
  private ParametersWithIV keyParamWithIV = null;
  
  public SymmetricEngine(String key, String iv) throws Exception {
    keyParamWithIV = new ParametersWithIV(new KeyParameter(key.getBytes("UTF-8")), iv.getBytes("UTF-8"), 0, 16);
  }
  
  public String encrypt(String plaintext) throws Exception {
    cipher.init(true, keyParamWithIV);
    byte[] plaintextBytes = plaintext.getBytes("UTF-8");
    byte[] ciphertextBytes = new byte[cipher.getOutputSize(plaintextBytes.length)];
    cipher.doFinal(ciphertextBytes,
        cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertextBytes, 0));
    return new String(Base64.encode(ciphertextBytes));
  }
  
  public String decrypt(String ciphertext) throws Exception {
    cipher.init(false, keyParamWithIV);
    byte[] ciphertextBytes = Base64.decode(ciphertext);
    byte[] plaintextBytes = new byte[cipher.getOutputSize(ciphertextBytes.length)];
    cipher.doFinal(plaintextBytes,
        cipher.processBytes(ciphertextBytes, 0, ciphertextBytes.length, plaintextBytes, 0));
    return new String(plaintextBytes);
  }
  
}
