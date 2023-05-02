/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package clients;

// Java program for Generating Hashes

import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Date;


public class Crypt {

    // Function that takes the string input
    // and returns the hashed string.
    public static String sha256(String input)
    {
        try {
            MessageDigest sha
                    = MessageDigest
                    .getInstance(
                            "SHA-256");
            int i = 0;

            byte[] hash
                    = sha.digest(
                    input.getBytes("UTF-8"));

            // hexHash will contain
            // the Hexadecimal hash
            StringBuffer hexHash
                    = new StringBuffer();

            while (i < hash.length) {
                String hex
                        = Integer.toHexString(
                        0xff & hash[i]);
                if (hex.length() == 1)
                    hexHash.append('0');
                hexHash.append(hex);
                i++;
            }

            return hexHash.toString();
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
// Java implementation for creating
// a block in a Blockchain


class Block implements Serializable {

    // Every block contains
    // a hash, previous hash and
    // data of the transaction made
    public String hash;
    public String previousHash;
    private String data;
    private long timeStamp;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    // Constructor for the block
    public Block(String data,
                 String previousHash)
    {
        this.data = data;
        this.previousHash
                = previousHash;
        this.timeStamp
                = new Date().getTime();
        this.hash
                = calculateHash();
    }



    // Function to calculate the hash
    public String calculateHash()
    {
        // Calling the "crypt" class
        // to calculate the hash
        // by using the previous hash,
        // timestamp and the data
        String calculatedhash
                = Crypt.sha256(
                previousHash
                        + Long.toString(timeStamp)
                        + data);

        return calculatedhash;
    }

    @Override
    public String toString() {
        return  hash + "\n" + previousHash + "\n" + data + "\n" + timeStamp ;
    }
}