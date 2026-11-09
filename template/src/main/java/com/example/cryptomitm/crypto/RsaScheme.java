package com.example.cryptomitm.crypto;

import com.example.cryptomitm.config.Config;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Chooses PKCS#1 v1.5 vs OAEP based on {@link Config#RSA_PADDING}. */
public final class RsaScheme {
    private RsaScheme() {}

    public static byte[] decrypt(String base64Cipher, PrivateKey key) throws GeneralSecurityException {
        if (Config.RSA_PADDING == Config.RsaPadding.OAEP) {
            return CryptoUtil.rsaOaepDecrypt(base64Cipher, key, Config.OAEP_HASH, Config.OAEP_MGF1_HASH);
        }
        return CryptoUtil.rsaPkcs1Decrypt(base64Cipher, key);
    }

    public static String encrypt(byte[] data, PublicKey key) throws GeneralSecurityException {
        if (Config.RSA_PADDING == Config.RsaPadding.OAEP) {
            return CryptoUtil.rsaOaepEncrypt(data, key, Config.OAEP_HASH, Config.OAEP_MGF1_HASH);
        }
        return CryptoUtil.rsaPkcs1Encrypt(data, key);
    }
}
