package com.example.cryptomitm.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Reusable crypto primitives for application-layer traffic decryption.
 *
 * Supports the two shapes seen most often in the wild:
 *   - RSA (PKCS#1 v1.5  and  OAEP with configurable hash + MGF1 hash)
 *   - AES-GCM (12-byte IV prepended to ciphertext, 128-bit tag) and AES-CBC
 *
 * All methods use the JDK's SunJCE provider; no Bouncy Castle is required for
 * these transformations (OAEP with MGF1-SHA1 is expressed via OAEPParameterSpec).
 */
public final class CryptoUtil {
    private CryptoUtil() {}

    private static final int GCM_IV_LEN  = 12;
    private static final int GCM_TAG_BITS = 128;

    // ------------------------------------------------------------------ keys

    /** Parse an X.509 SubjectPublicKeyInfo public key from base64 (PEM headers tolerated). */
    public static PublicKey publicKeyFromBase64(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(stripPem(b64));
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    /** Parse a PKCS#8 private key from base64 (PEM headers tolerated). */
    public static PrivateKey privateKeyFromBase64(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(stripPem(b64));
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static String stripPem(String s) {
        return s.replaceAll("-----BEGIN [^-]*-----", "")
                .replaceAll("-----END [^-]*-----", "")
                .replaceAll("\\s", "");
    }

    // ------------------------------------------------------- RSA PKCS#1 v1.5

    public static String rsaPkcs1Encrypt(byte[] data, PublicKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(c.doFinal(data));
    }

    public static byte[] rsaPkcs1Decrypt(String base64Cipher, PrivateKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(Base64.getDecoder().decode(base64Cipher));
    }

    // ------------------------------------------------------------- RSA OAEP
    // hash / mgf1Hash are JCA names, e.g. "SHA-256" and "SHA-1".
    // NOTE: many apps use a NON-default combo such as OAEP(SHA-256) with MGF1(SHA-1).
    //       You must match it exactly or decryption fails silently.

    private static OAEPParameterSpec oaep(String hash, String mgf1Hash) {
        return new OAEPParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgf1Hash), PSource.PSpecified.DEFAULT);
    }

    public static String rsaOaepEncrypt(byte[] data, PublicKey key, String hash, String mgf1Hash)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.ENCRYPT_MODE, key, oaep(hash, mgf1Hash));
        return Base64.getEncoder().encodeToString(c.doFinal(data));
    }

    public static byte[] rsaOaepDecrypt(String base64Cipher, PrivateKey key, String hash, String mgf1Hash)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.DECRYPT_MODE, key, oaep(hash, mgf1Hash));
        return c.doFinal(Base64.getDecoder().decode(base64Cipher));
    }

    // ------------------------------------------------- AES-GCM (iv prepended)

    public static String aesGcmEncrypt(String plaintext, String base64Key) throws GeneralSecurityException {
        byte[] key = Base64.getDecoder().decode(base64Key);
        requireAesKey(key);
        byte[] iv = new byte[GCM_IV_LEN];
        new SecureRandom().nextBytes(iv);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public static String aesGcmDecrypt(String base64Combined, String base64Key) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(base64Combined);
        byte[] key = Base64.getDecoder().decode(base64Key);
        requireAesKey(key);
        byte[] iv = Arrays.copyOfRange(all, 0, GCM_IV_LEN);
        byte[] ct = Arrays.copyOfRange(all, GCM_IV_LEN, all.length);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    // ---------------------------------------------- AES-CBC (explicit 16B IV)

    public static String aesCbcEncrypt(String plaintext, String base64Key, byte[] iv) throws GeneralSecurityException {
        byte[] key = Base64.getDecoder().decode(base64Key);
        requireAesKey(key);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return Base64.getEncoder().encodeToString(c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    public static String aesCbcDecrypt(String base64Cipher, String base64Key, byte[] iv) throws GeneralSecurityException {
        byte[] key = Base64.getDecoder().decode(base64Key);
        requireAesKey(key);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return new String(c.doFinal(Base64.getDecoder().decode(base64Cipher)), StandardCharsets.UTF_8);
    }

    private static void requireAesKey(byte[] key) throws GeneralSecurityException {
        if (key.length != 16 && key.length != 32) {
            throw new GeneralSecurityException("Invalid AES key length: " + key.length + " (need 16 or 32)");
        }
    }
}
