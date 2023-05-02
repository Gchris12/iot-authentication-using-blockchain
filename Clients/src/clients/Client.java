package clients;

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;
import java.util.stream.Stream;

// Client class
class Client implements Crypto {

    /**
     * @return The MAC Address as a String
     * @throws UnknownHostException
     * @throws SocketException
     */
    private static String getMac() throws UnknownHostException, SocketException {
        String add = "";
        try {

            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface network = networkInterfaces.nextElement();
                byte[] mac = network.getHardwareAddress();
                if (mac == null) {
                    System.out.println("null mac");
                } else {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                    }
                   add = sb.toString();
                    break;
                }
            }
        } catch (SocketException e) {

            e.printStackTrace();

        }

        return add;
    }

    /**
     * @return The IP Address as a String
     */
    private static String getIp() {
        String ip = "";

        try {
            DatagramSocket socket = new DatagramSocket();

            try {
                socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
                ip = socket.getLocalAddress().getHostAddress();
            } catch (Throwable var5) {
                try {
                    socket.close();
                } catch (Throwable var4) {
                    var5.addSuppressed(var4);
                }

                throw var5;
            }

            socket.close();
        } catch (UnknownHostException | SocketException var6) {
            var6.printStackTrace();
        }

        return ip;
    }

    /**
     * @return The Device's name as a String
     */
    private static String getMachineName() {
        String hostname = "Unknown";

        try {
            InetAddress addr = InetAddress.getLocalHost();
            hostname = addr.getHostName();
        } catch (UnknownHostException var2) {
            System.out.println("Hostname can not be resolved");
        }

        return hostname;
    }

    /**
     * @return A random generated String used
     * as password and username
     */
    private static String generateRandomPassword() {
        String chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%&";
        Random rnd = new Random();
        StringBuilder sb = new StringBuilder(8);

        for (int i = 0; i < 8; ++i) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }

        return sb.toString();
    }


    static void processFile(Cipher ci, InputStream in, OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }
    /**
     * Creates a temp file that includes:
     * MAC Address
     * IP Address
     * Username
     * Password
     * Device Name
     * @param Filename
     * @throws IOException
     */
    static void generateTempFile(String Filename) throws IOException {
        final String username = generateRandomPassword();
        final String password = generateRandomPassword();
        File f = new File(Filename);
        Date last;
        Duration diff;
        long diffDays;
        String var10001;
        long time;
        if (f.exists() && !f.isDirectory()) {
            time = f.lastModified();
            last = new Date(time);
            diff = Duration.between(Crypto.convertToLocalDateViaMillisecond(last).atStartOfDay(), LocalDate.now().atStartOfDay());
            diffDays = diff.toDays();
            if (diffDays >= 30L) {
                PrintWriter writer = new PrintWriter(f);
                writer.print("");
                writer.close();
                Path var10000 = Path.of(Filename);
                var10001 = getMac();
                Files.writeString(var10000, var10001 + "\n" + getIp() + "\n" + getMachineName() + "\n" + username + "\n" + password);
            }
        } else {
            Path tempFile = Files.createFile(Path.of(Filename));
            var10001 = getMac();
            Files.writeString(tempFile, var10001 + "\n" + getIp() + "\n" + getMachineName() + "\n" + username + "\n" + password);
        }
    }



    public static void copyContent(String a, String b)
            throws Exception
    {
        File first = new File(a);
        File second = new File(b);

        try (FileInputStream in = new FileInputStream(first); FileOutputStream out = new FileOutputStream(second)) {

            int n;

            // read() function to read the
            // byte of data
            while ((n = in.read()) != -1) {
                // write() function to write
                // the byte of data
                out.write(n);
            }
            in.close();
            out.close();

        }


    }
    public static String fileToString(String fileName){
        Path filePath = Path.of(fileName);
        StringBuilder contentBuilder = new StringBuilder();

        try (Stream<String> stream
                     = Files.lines(Paths.get(filePath.toUri()), StandardCharsets.UTF_8))
        {
            //Read the content with Stream
            stream.forEach(s -> contentBuilder.append(s).append("\n"));
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return contentBuilder.toString();

    }

    public static String getUsername(String filename){
        String content = fileToString(filename);
        String[] arrOfStr = content.split("\n", 5);
        return arrOfStr[3].replace("\n","");
    }

    public static String getPassword(String filename){
        String content = fileToString(filename);
        String[] arrOfStr = content.split("\n", 5);
        return arrOfStr[4].replace("\n","");
    }
    public static void appendToFileUsingFileWriter(String fileName,String context)
            throws IOException {

        FileWriter fw = new FileWriter(fileName, true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write("\n"+ context);
        bw.close();
    }

}
