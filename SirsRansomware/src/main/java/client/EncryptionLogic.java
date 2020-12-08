package client;

import server.Server;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A simple client that requests a greeting from the {@link Server} with TLS.
 */
public class EncryptionLogic {
    private final static int ITERATIONS = 10000;

    public EncryptionLogic() {
    }

    public KeyPair generateUserKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(2048, random);
            keyPair = keyGen.genKeyPair();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    public byte[] generateSecurePassword(String password, byte[] salt) {
        byte[] key = null;
        try {
            char[] chars = password.toCharArray();
            //rafa edit: this is just to demonstrate how to generate a PBKDF2 password-based kdf
            // because the salt needs to be the same
            //byte[] salt = PBKDF2Main.getNextSalt();

            PBEKeySpec spec = new PBEKeySpec(chars, salt, EncryptionLogic.ITERATIONS, 256 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            key = skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return key;
    }

    public byte[] createDigitalSignature(byte[] fileBytes, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withRSA");

        //Initialize the signature
        sign.initSign(privateKey);

        //Adding data to the signature
        sign.update(fileBytes);
        //Calculating the signature

        return sign.sign();
    }

    public boolean verifyDigitalSignature(byte[] message, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withRSA");
        //Initializing the signature

        sign.initVerify(publicKey);
        sign.update(message);

        //Verifying the signature
        return sign.verify(signature);
    }

    public PublicKey getPublicKey(byte[] ownerPublicKey) {
        return (PublicKey) bytesToPubKey(ownerPublicKey);
    }

    public PrivateKey getPrivateKey(String username, KeyStore keyStore) {
        PrivateKey privateKey = null;
        try {
            //TODO provide a password
            privateKey = (PrivateKey) keyStore.getKey(username + "privkey", "".toCharArray());
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public List<byte[]> getOthersAESEncrypted(List<byte[]> othersPubKeys, byte[] aesKey) {
        List<byte[]> othersAESEncrypted = new ArrayList<>();
        for (byte[] bytes : othersPubKeys) {
            othersAESEncrypted.add(encryptWithRSA(bytesToPubKey(bytes), aesKey));
        }
        return othersAESEncrypted;
    }

    public byte[] getAESKeyBytes(byte[] AESEncryptedBytes, String username, KeyStore keyStore) {
        return decryptWithRSA(getPrivateKey(username, keyStore), AESEncryptedBytes);
    }

    public SecretKey generateAESKey() {

        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        SecureRandom secRandom = new SecureRandom();

        Objects.requireNonNull(keyGen).init(256, secRandom);

        return keyGen.generateKey();

    }

    public byte[] decryptSecureFile(byte[] file_bytes, byte[] AESEncrypted, byte[] iv, String username, KeyStore keyStore) throws BadPaddingException, IllegalBlockSizeException {
        byte[] aesKeybytes = getAESKeyBytes(AESEncrypted, username, keyStore);
        SecretKey aesKey = bytesToAESKey(aesKeybytes);
        return decryptWithAES(aesKey, file_bytes, iv);
    }

    public byte[] decryptWithAES(SecretKey secretKey, byte[] file_bytes, byte[] iv) throws BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        try {
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            return cipher.doFinal(file_bytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;

    }

    public byte[] encryptWithAES(SecretKey secretKey, byte[] file_bytes, byte[] iv) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            return cipher.doFinal(file_bytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] decryptWithRSA(Key decryptionKey, byte[] file_bytes) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, decryptionKey);
            return rsa.doFinal(file_bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] encryptWithRSA(Key encryptionKey, byte[] file_bytes) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            rsa.init(Cipher.ENCRYPT_MODE, encryptionKey);
            return rsa.doFinal(file_bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public Key bytesToPubKey(byte[] bytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(bytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKey bytesToAESKey(byte[] bytes) {
        return new SecretKeySpec(bytes, 0, bytes.length, "AES");
    }

}
