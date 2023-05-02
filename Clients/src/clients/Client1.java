package clients;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.Scanner;


// Client class
class Client1 extends Client{


    // driver code
    public static void main(String[] args) throws Exception {
        generateTempFile("temp1.txt");
        Crypto.generateKeys("Client1");
        PrivateKey pri = Crypto.loadPrivate("Client1.key");
        Crypto.sign("temp1.txt",pri);


        // establish a connection by providing host and port
        // number
        try (Socket socket = new Socket("192.168.1.1", 1235)) {

            // writing to server
            PrintWriter out = new PrintWriter(
                    socket.getOutputStream(), true);

            // reading from server
            BufferedReader in
                    = new BufferedReader(new InputStreamReader(
                    socket.getInputStream()));

            // object of scanner class
            Scanner sc = new Scanner(System.in);
            String line = null;

            while (!"exit".equalsIgnoreCase(line)) {

                // reading from user
                line = sc.nextLine();

                // sending the user input to server
                out.println(line);
                out.flush();

                // displaying server reply
                if("Authentication".equalsIgnoreCase(line)){
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, Crypto.loadPrivate("Client1.key"));
                    try (FileInputStream filein = new FileInputStream("temp1.txt");
                         FileOutputStream fileout = new FileOutputStream("temp1.txt.enc")) {
                        processFile(cipher, filein, fileout);
                    }
                    ObjectInputStream obji = new ObjectInputStream(socket.getInputStream());
                    PublicKey serverpub = (PublicKey) obji.readObject();
                    String hash = (Crypto.checksum("temp1.txt.enc"));


                    // First create an AES Key
                    String secretAESKeyString = Crypto.getSecretAESKeyAsString();


                    Timestamp timestamp = new Timestamp(System.currentTimeMillis()); // Timestamp for the packet





                    // Encrypt AES Key with RSA Private Key
                    String encryptedAESKeyString = Crypto.encryptAESKey(secretAESKeyString + "\n" + timestamp.getTime(), serverpub);



                    out.println(encryptedAESKeyString);
                    out.flush();
                    String encryptedText = Crypto.encryptTextUsingAES(hash + "\n" + timestamp.getTime(), secretAESKeyString); //encrypted hash and timestamp with aes key
                    out.println(encryptedText);
                    out.flush();
                    String encryptedUsername = Crypto.encryptTextUsingAES(getUsername("temp1.txt") + "\n" + timestamp.getTime(), secretAESKeyString); //encrypted username and timestamp with aes key
                    out.println(encryptedUsername);
                    out.flush();
                    String encryptedPassword = Crypto.encryptTextUsingAES(getPassword("temp1.txt") + "\n" + timestamp.getTime(), secretAESKeyString); //encrypted password and timestamp with aes key
                    out.println(encryptedPassword);
                    out.flush();

                switch(Integer.parseInt(in.readLine())){
                    case 1: System.out.println("Not in HashMap");
                      break;
                    case 2: System.out.println("Not in Blockchain");
                      break;
                    case 3: System.out.println("Time Error");
                      break;
                    case 4: System.out.println("Authenticated Succesfully");
                      break;
                    case 5: System.out.println("Wrong Credentials");
                      break;
                      default:
                        System.out.println("Something went wrong");
                }

                }
                else if("Registration".equalsIgnoreCase(line)){
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, Crypto.loadPrivate("Client1.key"));
                    try (FileInputStream filein = new FileInputStream("temp1.txt");
                         FileOutputStream fileout = new FileOutputStream("temp1.txt.enc")) {
                        processFile(cipher, filein, fileout);
                    }
                    ObjectInputStream obji = new ObjectInputStream(socket.getInputStream());
                    PublicKey serverpub = (PublicKey) obji.readObject();
                    String hash = (Crypto.checksum("temp1.txt.enc"));
                    copyContent("temp1.txt","temp1.reg");
                    appendToFileUsingFileWriter("temp1.reg",hash);

                    Timestamp timestamp = new Timestamp(System.currentTimeMillis());

                    // First create an AES Key
                    String secretAESKeyString = Crypto.getSecretAESKeyAsString();



                    // Encrypt our data with AES key
                    String encryptedText = Crypto.encryptTextUsingAES(fileToString("temp1.reg")  + timestamp.getTime(), secretAESKeyString);

                    // Encrypt AES Key with RSA Private Key
                    String encryptedAESKeyString = Crypto.encryptAESKey(secretAESKeyString + "\n" + timestamp.getTime(), serverpub);

                    out.println(encryptedAESKeyString);
                    out.flush();
                    out.println(encryptedText);
                    out.flush();
                    
                    switch(Integer.parseInt(in.readLine())){
                        case 1: System.out.println("Time error");
                        break;
                        case 2: System.out.println("Hash Already Exists");
                        break;
                        case 3: System.out.println("Registered Succesfully");
                        break;
                         default:
                        System.out.println("Something went wrong");
                    }
                }
                else{
                System.out.println("Wrong Input " + "" + line + "");
                }



            }

            // closing the scanner object

            out.println("exit");
            out.flush();
            out.close();
            socket.close();
            in.close();
            sc.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}