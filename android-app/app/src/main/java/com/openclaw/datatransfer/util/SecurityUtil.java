package com.openclaw.datatransfer.util;

import java.io.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM encryption/decryption with PBKDF2 key derivation.
 * Compatible with the Windows backup_manager.py SecurityManager.
 */
public class SecurityUtil {

    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int PBKDF2_ITERATIONS = 600_000;

    /**
     * Derive AES-256 key from password and salt using PBKDF2-HMAC-SHA256.
     */
    public static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Decrypt a file encrypted by the Windows app.
     * File format: [16-byte salt][12-byte nonce][ciphertext+tag]
     */
    public static boolean decryptFile(File inputFile, File outputFile, String password) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Read salt
            byte[] salt = new byte[SALT_LENGTH];
            if (fis.read(salt) != SALT_LENGTH) return false;

            // Read nonce
            byte[] nonce = new byte[NONCE_LENGTH];
            if (fis.read(nonce) != NONCE_LENGTH) return false;

            // Read ciphertext
            byte[] ciphertext = fis.readAllBytes();

            // Derive key
            SecretKey key = deriveKey(password, salt);

            // Decrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            byte[] plaintext = cipher.doFinal(ciphertext);

            fos.write(plaintext);
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Encrypt a file (for sending data back to Windows app).
     * Uses same format: [16-byte salt][12-byte nonce][ciphertext+tag]
     */
    public static boolean encryptFile(File inputFile, File outputFile, String password) {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] plaintext = fis.readAllBytes();

            // Generate salt and nonce
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);
            byte[] nonce = new byte[NONCE_LENGTH];
            random.nextBytes(nonce);

            // Derive key
            SecretKey key = deriveKey(password, salt);

            // Encrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            // Write: salt + nonce + ciphertext
            fos.write(salt);
            fos.write(nonce);
            fos.write(ciphertext);
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
