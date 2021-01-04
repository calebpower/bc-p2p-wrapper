package com.calebpower.crypto.bc;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;

public class AsymmetricEngine {
  
  private static final int KEY_SIZE = 64; // 64 bytes = 512 bits
  private static final String CHARSET = "UTF-8";
  private static final String CURVE = "secp384r1";
  
  public KeyPair genKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
    ECGenParameterSpec spec = new ECGenParameterSpec(CURVE);
    keyGen.initialize(spec, SecureRandom.getInstanceStrong());
    return keyGen.generateKeyPair();
  }
  
  public PublicKey regenPubkey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
    return KeyFactory.getInstance("EC")
        .generatePublic(new X509EncodedKeySpec(Base64.decode(key)));
  }
  
  public PrivateKey regenPrivkey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(key)));
  }
  
  public String encrypt(String plaintext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return new String(Base64.encode(cipher.doFinal(plaintext.getBytes(CHARSET))));
  }
  
  public String decrypt(String ciphertext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return new String(cipher.doFinal(Base64.decode(ciphertext)));
  }
  
  public String sign(String plaintext, PrivateKey ourKey) throws Exception {
    Signature sig = Signature.getInstance("SHA1WithECDSA");
    sig.initSign(ourKey);
    sig.update(plaintext.getBytes(CHARSET));
    return new String(Base64.encode(sig.sign()));
  }
  
  public boolean verify(String plaintext, String signature, PublicKey theirKey) throws Exception {
    Signature sig = Signature.getInstance("SHA1WithECDSA");
    sig.initVerify(theirKey);
    sig.update(plaintext.getBytes(CHARSET));
    try {
      if(sig.verify(Base64.decode(signature))) return true;      
    } catch(SignatureException e) { }
    
    return false;
  }
  
}
