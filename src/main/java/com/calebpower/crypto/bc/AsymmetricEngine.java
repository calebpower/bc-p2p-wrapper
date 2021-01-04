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

/**
 * Encrypts, decrypts, signs, and verifies with asymmetric keys.
 * Generates said keys with the appropriate curve.
 * 
 * - Encryption: ECIES
 * - Signing: ECDSA w/ SHA512
 * - Curve: secp384r1 (P-384)
 * 
 * @author Caleb L. Power
 */
public class AsymmetricEngine {
  
  private static final String CHARSET = "UTF-8";
  private static final String CURVE = "secp384r1";
  
  /**
   * Securely generates a pseudorandom elliptic curve keypair.
   * 
   * @return a KeyPair containing private and public keys
   * @throws InvalidAlgorithmParameterException if the developer got something wrong
   * @throws NoSuchAlgorithmException if the developer got something wrong
   * @throws NoSuchProviderException if the developer got something wrong
   */
  public KeyPair genKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
    ECGenParameterSpec spec = new ECGenParameterSpec(CURVE);
    keyGen.initialize(spec, SecureRandom.getInstanceStrong());
    return keyGen.generateKeyPair();
  }
  
  /**
   * Regenerates an elliptic curve public key object from a Base64-encoded byte array.
   * 
   * @param key the Base64-encoded key
   * @return the PublicKey encapsulation
   * @throws NoSuchAlgorithmException if the developer got something wrong
   * @throws InvalidKeySpecException if the developer got something wrong
   */
  public PublicKey regenPubkey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
    return KeyFactory.getInstance("EC")
        .generatePublic(new X509EncodedKeySpec(Base64.decode(key)));
  }
  
  /**
   * Regenerates an elliptic curve private key object from a Base64-encoded byte array.
   * 
   * @param key the Base64-encoded key
   * @return the PrivateKey encapsulation
   * @throws InvalidKeySpecException if the developer got something wrong
   * @throws NoSuchAlgorithmException if the developer got something wrong
   */
  public PrivateKey regenPrivkey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(key)));
  }
  
  /**
   * Encrypts plaintext for decryption by another party.
   * 
   * @param plaintext the plaintext
   * @param ourKey our private key
   * @param theirKey their public key
   * @return Base64-encoded ciphertext
   * @throws Exception if something went wrong
   */
  public String encrypt(String plaintext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return new String(Base64.encode(cipher.doFinal(plaintext.getBytes(CHARSET))));
  }
  
  /**
   * Decrypts ciphertext received from another party.
   * 
   * @param ciphertext the ciphertext
   * @param ourKey our private key
   * @param theirKey their public key
   * @return a String representation of the original plaintext
   * @throws Exception if something went wrong
   */
  public String decrypt(String ciphertext, PrivateKey ourKey, PublicKey theirKey) throws Exception {
    Cipher cipher = Cipher.getInstance("ECIES");
    
    // generate derivation and encoding vectors
    byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
    IESParameterSpec param = new IESParameterSpec(d, e, 256);
    
    cipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(ourKey, theirKey), param);
    return new String(cipher.doFinal(Base64.decode(ciphertext)));
  }
  
  /**
   * Signs plaintext and returns the signature.
   * 
   * @param plaintext the plaintext
   * @param ourKey our private key
   * @return Base64 representation of the signature
   * @throws Exception if something went wrong
   */
  public String sign(String plaintext, PrivateKey ourKey) throws Exception {
    Signature sig = Signature.getInstance("SHA512WithECDSA");
    sig.initSign(ourKey);
    sig.update(plaintext.getBytes(CHARSET));
    return new String(Base64.encode(sig.sign()));
  }
  
  /**
   * Verifies the signature associated with some plaintext.
   * 
   * @param plaintext the plaintext
   * @param signature the signature
   * @param theirKey the sender's public key
   * @return {@code true} iff the signature was appropriately verified
   * @throws Exception if something went wrong
   */
  public boolean verify(String plaintext, String signature, PublicKey theirKey) throws Exception {
    Signature sig = Signature.getInstance("SHA512WithECDSA");
    sig.initVerify(theirKey);
    sig.update(plaintext.getBytes(CHARSET));
    try {
      if(sig.verify(Base64.decode(signature))) return true;      
    } catch(SignatureException e) { }
    
    return false;
  }
  
}
