package com.calebpower.crypto.bc;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

public class AsymmetricEngine {
  
  private static final int KEY_SIZE = 64; // 64 bytes = 512 bits
  private static final String CHARSET = "UTF-8";
  private static final String CURVE = "secp384r1";
  
  private ECGenParameterSpec spec = new ECGenParameterSpec(CURVE);
  private KeyPairGenerator keyGen = null;
  
  public AsymmetricEngine() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    this.keyGen = KeyPairGenerator.getInstance("EC");
    this.keyGen.initialize(spec, SecureRandom.getInstanceStrong());
  }
  
  public KeyPair genKey() {
    return keyGen.generateKeyPair();
  }
  
  public byte[] encrypt(byte[] plaintext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return cipher.doFinal(plaintext);
  }
  
  public byte[] decrypt(byte[] ciphertext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return cipher.doFinal(ciphertext);
  }
  
  public byte[] sign(byte[] plainText, PrivateKey ourKey) throws Exception {
    Signature sig = Signature.getInstance("SHA1WithECDSA");
    sig.initSign(ourKey);
    sig.update(plainText);
    return sig.sign();
  }
  
  public boolean verify(byte[] plaintext, byte[] signature, PublicKey theirKey) throws Exception {
    Signature sig = Signature.getInstance("SHA1WithECDSA");
    sig.initVerify(theirKey);
    sig.update(plaintext);
    try {
      if(sig.verify(signature)) return true;      
    } catch(SignatureException e) { }
    
    return false;
  }
  
}
