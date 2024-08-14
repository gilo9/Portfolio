package org.example;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;

class Client {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("java Client <host> <port> <userId>");

        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        try {
            Socket s = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            DataInputStream dis = new DataInputStream(s.getInputStream());

            dos.writeUTF(hash(userId));

            System.out.println("\nClient Program (user " + userId + ") \n --------- ");

            boolean message = dis.readBoolean();
            if (message) {
                int x = dis.readInt();
                System.out.println("\nYou have " + x + " new message(s)");

                for (int a = 0; a < x; a++) {
                    //read signature
                    int sigLen = dis.readInt();
                    byte[] signature = new byte[sigLen];
                    dis.readFully(signature);

                    //read EncrytedMsg
                    int msgLength = dis.readInt();
                    byte[] encryptedMsg = new byte[msgLength];
                    dis.readFully(encryptedMsg);

                    String date = dis.readUTF();

                    byte[] msgBytes = DecrpytRSA(encryptedMsg, readPrivateKey(userId));

                    boolean b = verify(signature,msgBytes,readPublicKey("server"));
                    if (b){
                        String msg = new String(msgBytes, "UTF8");

                        System.out.println("\nDate:" + date);
                        System.out.println("Message: " + msg + "\n");

                    }else{
                        System.out.println("Signature cannot be verified");
                        s.close();
                    }
                }
            } else {
                System.out.println("You have 0 new message(s).");
            }

            System.out.println("Would you like to send a message? (y/n)");
            Scanner sc = new Scanner(System.in);
            if (sc.nextLine().equals("y")) {

                dos.writeBoolean(true);
                dos.writeUTF(userId);

                System.out.println("Enter the recipient userid:");
                String recipient = sc.next();
                sc.nextLine();
                System.out.println("Enter a message:");
                String msg = sc.nextLine();

                msg = msg + ":" + recipient;

                DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
                LocalDateTime time = LocalDateTime.now();
                String dateString = time.format(dtf);


                RSAPublicKey pubKey  = readPublicKey("server");


                RSAPrivateKey privateKey = readPrivateKey(userId);

                //sender signature
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(privateKey);
                sig.update(msg.getBytes("UTF8"));
                byte[] signature = sig.sign();

                byte[] msgBytes = EncrpytRSA(msg.getBytes(), pubKey);

                dos.writeUTF(dateString);
                dos.writeInt(signature.length);
                dos.write(signature);
                dos.writeInt(msgBytes.length);
                dos.write(msgBytes);

                dos.writeUTF(userId);

                String OK = dis.readUTF();
                if ("OK".equals(OK)) {
                    System.out.println("\nMessage sent");
                } else {
                    System.out.println("\nFailed");
                    s.close();
                }
            } else {
                dos.writeBoolean(false);
                s.close();
            }
        } catch (Exception e) {
            System.err.println("Cannot connect to server");
        }
    }

    private static RSAPrivateKey readPrivateKey(String userId) {
        try {

            KeyFactory kf = KeyFactory.getInstance("RSA");
            File f = new File(userId + ".prv");
            byte[] prvBytes = Files.readAllBytes(f.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
            return (RSAPrivateKey) kf.generatePrivate(prvSpec);

        } catch (NoSuchAlgorithmException e) {
            System.err.println("RSA algorithm is not available in the environment");
        } catch (IOException e) {
            System.err.println("Error reading the private key file");
        } catch (InvalidKeySpecException e) {
            System.err.println("Invalid key specification");
        } catch (Exception e) {
            System.err.println("An unexpected error occurred");
            e.printStackTrace();
        }
        return null;
    }

    private static RSAPublicKey readPublicKey(String userId) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            File f = new File(userId+".pub");
            byte[] pubBytes = Files.readAllBytes(f.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
            return (RSAPublicKey) kf.generatePublic(pubSpec);
        } catch (Exception e) {
            System.err.println("An unexpected error occurred");
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] DecrpytRSA(byte[] encryptedMsg, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] msgBytes = cipher.doFinal(encryptedMsg);
            return msgBytes;
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] EncrpytRSA(byte[] msgBytes, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrytedMsg = cipher.doFinal(msgBytes);
            return encrytedMsg;
        } catch (Exception e) {
            return null;
        }

    }

    private static String hash(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update("gfhk2024:".getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte a : md.digest(text.getBytes())) sb.append(String.format("%02X", a));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
    private static boolean verify(byte[] signature, byte[] msgBytes, RSAPublicKey key){
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update(msgBytes);
            return sig.verify(signature);
        }catch(Exception e){
            System.err.println("An unexpected error has occurred");
            e.printStackTrace();
            return false;
        }
    }


}