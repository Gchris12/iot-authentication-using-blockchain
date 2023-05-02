/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static java.lang.System.out;

// Java implementation to store
// blocks in an ArrayList
// Server class

class Server implements Crypto {
    final static String outputFilePath = "hashMap.txt";
    private static ArrayList<Block> blockchain= new ArrayList<>();
    private static HashMap<String, String> id = new HashMap<String, String>();
    public static void readHashMapFromFile() {
        File a = new File(outputFilePath);
        if (a.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(outputFilePath))) {
                while ((line = reader.readLine()) != null) {
                    String[] keyValuePair = line.split(":", 2);
                    if (keyValuePair.length > 1) {
                        String key = keyValuePair[0];
                        String value = keyValuePair[1];
                        id.put(key, value);
                    } else {
                        out.println("No Key:Value found in line, ignoring: " + line);
                    }
                }
            } catch (IOException e) {
            }
        }
    }
  
    private static void writeHashMapToFile() {
        // new file object
        File file = new File(outputFilePath);

        BufferedWriter bf = null;

        try {

            // create new BufferedWriter for the output file
            bf = new BufferedWriter(new FileWriter(file));

            // iterate map entries
            for (Map.Entry<String, String> entry :
                    id.entrySet()) {

                // put key and value separated by a colon
                bf.write(entry.getKey() + ":"
                        + entry.getValue());

                // new line
                bf.newLine();
            }

            bf.flush();
        } catch (IOException e) {
        } finally {

            try {

                // always close the writer
                assert bf != null;
                bf.close();
            } catch (IOException ignored) {
            }
        }
    }
    public static Block returnBlock(String hash){
        int i ;
        boolean found = false;
        for (i = 0 ; i < blockchain.size(); i++){
            if(blockchain.get(i).hash.equals(id.get(hash))){
                found = true;
                break;
            }
        }
         if (found)
            return blockchain.get(i);
         else
             return null;
    }
    public static boolean checkCredentials(String decryptedText,String decryptedUsername,String decryptedPassword){
        String data[] = returnBlock(decryptedText).getData().split("\n");
        String username = data[3];
        String password = data[4];      
        return password.equals(decryptedPassword) && username.equals(decryptedUsername);
            
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Crypto.generateKeys("Server"); //generate private and public key of server
        ServerSocket server = null ;
        readHashMapFromFile();
        try {

            // server is listening on port 1235
            server = new ServerSocket(1235);
            server.setReuseAddress(true);

            // running infinite loop for getting
            // client request
            while (true) {

                // socket object to receive incoming client
                // requests
                Socket client = server.accept();

                // Displaying that new client is connected
                // to server
                out.println("New client connected "
                        + client.getInetAddress()
                        .getHostAddress());

                // create a new thread object
                ClientHandler clientSock
                        = new ClientHandler(client);

                // This thread will handle the client
                // separately
                new Thread(clientSock).start();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if (server != null) {
                try {
                    server.close();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // ClientHandler class
    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final PrivateKey pri = Crypto.loadPrivate("Server.key");

        // Constructor
        public ClientHandler(Socket socket) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
            this.clientSocket = socket;
        }

        public void run()
        {
         
            ObjectInputStream ois = null;
            try {
                File a = new File("blockchain.dat");
                if(a.exists()) {
                    ois = new ObjectInputStream(new FileInputStream("blockchain.dat"));
                    blockchain = (ArrayList<Block>) ois.readObject();
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }

            PrintWriter out = null;
            BufferedReader in = null;
           
            try {

                // get the outputstream of client
                out = new PrintWriter(
                        clientSocket.getOutputStream(), true);

                // get the inputstream of client
                in = new BufferedReader(
                        new InputStreamReader(
                                clientSocket.getInputStream()));

                String line =  in.readLine();
                   
                while (!"Exit".equalsIgnoreCase(line)) {
                    System.out.println(line);
                    if("Authentication".equalsIgnoreCase(line)){
                        boolean time = true;
                        ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
                        objectOutputStream.writeObject(Crypto.loadPublic("Server.pub"));
                        objectOutputStream.flush();

                        // First decrypt the AES Key with RSA Public key
                        String[] deTemp = Crypto.decryptAESKey(in.readLine(), pri).split("\n"); //decrypt aes key with rsa key
                        String decryptedAESKeyString = deTemp[0];
                        Timestamp temp1 = new Timestamp(System.currentTimeMillis());
                        Timestamp temp2 = new Timestamp(Long.parseLong(deTemp[1]));
                        time &= Crypto.compareTime(temp2,temp1); //check timestamp

                        // Now decrypt data using the decrypted AES key!
                        String[] dText = Crypto.decryptTextUsingAES(in.readLine(), decryptedAESKeyString).split("\n");
                        String decryptedText =dText[0];
                        temp1 = new Timestamp(System.currentTimeMillis());
                        temp2 = new Timestamp(Long.parseLong(dText[1]));
                        time &= Crypto.compareTime(temp2,temp1);


                        //username
                        String[] tempUsername = Crypto.decryptTextUsingAES(in.readLine(), decryptedAESKeyString).split("\n");
                        String decryptedUsername = tempUsername[0];
                        temp1 = new Timestamp(System.currentTimeMillis());
                        temp2 = new Timestamp(Long.parseLong(tempUsername[1]));
                        time &= Crypto.compareTime(temp2,temp1);

                        //password
                        String[] tempPassword = Crypto.decryptTextUsingAES(in.readLine(), decryptedAESKeyString).split("\n");
                        String decryptedPassword = tempPassword[0];
                        temp1 = new Timestamp(System.currentTimeMillis());
                        temp2 = new Timestamp(Long.parseLong(tempPassword[1]));
                        time &= Crypto.compareTime(temp2,temp1);

                        if (!id.containsKey(decryptedText)){
                            System.out.println("Not in HashMap");
                            out.println("1");
                            out.flush(); 
                        }
                        
                        else if (returnBlock(decryptedText) == null){
                            System.out.println("Not in blockchain");
                            out.println("2");
                            out.flush();
                        }
                        
                        else if (!time){
                            System.out.println("Time error");
                            out.println("3");
                            out.flush();
                        }
            
                        else if (checkCredentials(decryptedText,decryptedUsername,decryptedPassword)){
                            System.out.println("Authenticated Succesfully");
                            out.println("4");
                            out.flush();
                        }
                        
                        else {
                            System.out.println("Wrong credentials");
                            out.println("5");
                            out.flush();
                        }
                       
                         line = in.readLine();

                    }
                    else if("Registration".equalsIgnoreCase(line)){
                        ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
                        objectOutputStream.writeObject(Crypto.loadPublic("Server.pub"));
                        objectOutputStream.flush();

                        boolean time = true;
                        // First decrypt the AES Key with RSA Public key
                        String[] deTemp = Crypto.decryptAESKey(in.readLine(), pri).split("\n"); //decrypt aes key with rsa key
                        String decryptedAESKeyString = deTemp[0];
                        Timestamp temp1 = new Timestamp(System.currentTimeMillis());
                        Timestamp temp2 = new Timestamp(Long.parseLong(deTemp[1]));
                        time &= Crypto.compareTime(temp2,temp1); //check timestamp

                        // Now decrypt data using the decrypted AES key!
                        String decryptedText = Crypto.decryptTextUsingAES(in.readLine(), decryptedAESKeyString);




                        String[] temp = decryptedText.split("\n");
                        temp1 = new Timestamp(System.currentTimeMillis());
                        temp2 = new Timestamp(Long.parseLong(temp[6]));
                        time &= Crypto.compareTime(temp2,temp1); //check timestamp
                        String hash = temp[5];
                        String data = temp[0] + "\n" + temp[1] + "\n" + temp[2] + "\n" + temp[3] + "\n" +temp[4];

                        // Adding the data to the ArrayList
                           if(!time){
                               System.out.println("Time error");
                                out.println("1");
                                out.flush();
                               
                           }
                            else if (!id.containsKey(hash)) {
                            Block tempBlock;
                            if (blockchain.isEmpty()) {
                                tempBlock = new Block(data, "0");
                            }
                            else {
                                tempBlock = new Block(data,blockchain.get(blockchain.size()-1).hash);
                            }
                            blockchain.add(tempBlock);
                            id.put(hash, tempBlock.hash);
                            try (ObjectOutputStream oos = new ObjectOutputStream(  new FileOutputStream("blockchain.dat"))) {
                                oos.writeObject(blockchain);
                            }
                            writeHashMapToFile();
                            System.out.println("Value registered");
                            out.println("3");
                            out.flush();


                        } else {
                            System.out.println("Already exists");
                            out.println("2");
                            out.flush();
                        }
                        line = in.readLine();
                      }
                    else if (line == null){
                        System.out.println("Client send null, exiting...");
                     try {
                    out.close();
                    }
 
                    finally {
                        try {
                            in.close();
                            }
 
                    finally {
                        clientSocket.close();
                    }
                    }    
                        
                    }
                    else{
                        System.out.println("Wrong input ");
                        line = in.readLine();
                    }

                }
                System.out.print("Client exited" );
               
                
            }
            catch (Exception e) {
               
            }
          
            }
        }
    }
