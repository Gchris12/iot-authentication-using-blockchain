/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package server;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

public interface Crypto extends Serializable {
    public static ArrayList<Block> blockchain= new ArrayList<Block>();
    /**
     * Generates and stores the Public and Private keys
     * @param a
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */

    static boolean compareTime(Timestamp a, java.sql.Timestamp b){
        if (Math.abs(a.getTime()-b.getTime()) < 200){
            System.out.println(Math.abs(a.getTime()-b.getTime()));
            return true;
        }
        else{
            System.out.println(Math.abs(a.getTime()-b.getTime()));
            return false;
        }
    }
    static void generateKeys(String filename) throws NoSuchAlgorithmException, IOException {
        File f = new File(filename+".pub");
        Date last;
        Duration diff;
        long diffDays;
        long time;
        if (f.exists() && !f.isDirectory()) {
            time = f.lastModified();
            last = new Date(time);
            diff = Duration.between(convertToLocalDateViaMillisecond(last).atStartOfDay(), LocalDate.now().atStartOfDay());
            diffDays = diff.toDays();
            if (diffDays >= 30L) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                Key pub = kp.getPublic();
                Key pvt = kp.getPrivate();
                FileOutputStream out = new FileOutputStream(filename + ".key");
                out.write(pvt.getEncoded());
                out.close();
                out = new FileOutputStream(filename + ".pub");
                out.write(pub.getEncoded());
                out.close();
            }
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Key pub = kp.getPublic();
            Key pvt = kp.getPrivate();
            FileOutputStream out = new FileOutputStream(filename + ".key");
            out.write(pvt.getEncoded());
            out.close();
            out = new FileOutputStream(filename + ".pub");
            out.write(pub.getEncoded());
            out.close();
        }
    }

    /**
     * @param dateToConvert
     * @return The converted date
     */
    static LocalDate convertToLocalDateViaMillisecond(Date dateToConvert) {
        return Instant.ofEpochMilli(dateToConvert.getTime()).atZone(ZoneId.systemDefault()).toLocalDate();
    }

    /**
     * Loads private key from file
     * @param keyFile
     * @return
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    static PrivateKey loadPrivate(String keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        /* Read all bytes from the private key file */
        Path path = Paths.get(keyFile);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);

    }

    /**
     * Calculates the checksum(HASH) of a file, using SHA-256
     * @param filepath
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    static String checksum(String filepath) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        // file hashing with DigestInputStream
        try (DigestInputStream dis = new DigestInputStream(new FileInputStream(filepath), md)) {
            while (dis.read() != -1) ; //empty loop to clear the data
            md = dis.getMessageDigest();
        }

        // bytes to hex
        StringBuilder result = new StringBuilder();
        for (byte b : md.digest()) {
            result.append(String.format("%02x", b));
        }
        return result.toString();

    }
    /**
     * Signs a file
     * @param filename
     * @param privateKey
     * @throws Exception
     */
    static void sign(String filename, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        byte[] messageBytes = Files.readAllBytes(Paths.get(String.valueOf(filename)));

        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();
        Files.write(Paths.get(filename+"_digital_signature"), digitalSignature);
    }
    /**
     * Loads Public key from file
     * @param keyFile
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    static PublicKey loadPublic(String keyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyFile);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);

    }
    // Decrypt text using AES key
    static String decryptTextUsingAES(String encryptedText, String aesKeyString) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytePlainText);
    }


    // Decrypt AES Key using RSA private key
    static String decryptAESKey(String encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
    }
    // Create a new AES key. Uses 256 bit (strong)
    public static String getSecretAESKeyAsString() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return Base64.getEncoder().encodeToString(secKey.getEncoded());

    }
    // Encrypt text using AES key
    public static String encryptTextUsingAES(String plainText, String aesKeyString) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(byteCipherText);
    }
    // Encrypt AES Key using RSA public key
    static String encryptAESKey(String plainAESKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
    }

// Java implementation to check
// validity of the blockchain

    // Function to check
// validity of the blockchain
    public static Boolean isChainValid()
    {
        Block currentBlock;
        Block previousBlock;

        // Iterating through
        // all the blocks
        for (int i = 1;
             i < blockchain.size();
             i++) {

            // Storing the current block
            // and the previous block
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i - 1);

            // Checking if the current hash
            // is equal to the
            // calculated hash or not
            if (!currentBlock.hash
                    .equals(
                            currentBlock
                                    .calculateHash())) {
                System.out.println(
                        "Hashes are not equal");
                return false;
            }

            // Checking of the previous hash
            // is equal to the calculated
            // previous hash or not
            if (!previousBlock
                    .hash
                    .equals(
                            currentBlock
                                    .previousHash)) {
                System.out.println(
                        "Previous Hashes are not equal");
                return false;
            }
        }

        // If all the hashes are equal
        // to the calculated hashes,
        // then the blockchain is valid
        return true;
    }
}
