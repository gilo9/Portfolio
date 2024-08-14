package org.example;
import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

class Server {
    private static ConcurrentHashMap<String , List<Message>> messagesMap = new ConcurrentHashMap<>();
    static class Message{
        byte[] message;
        String date;
        byte[] signature;
        Message(byte[] message, String date, byte[] signature){
            this.message=  message;
            this.date = date;
            this.signature = signature;
        }
    }

    public static void main(String[] args) throws Exception {
        if(args.length <1){
            System.out.println("java Server <port> ");
            return;
        }
        //Starting Server
        int port = Integer.parseInt(args[1]);
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");

        while(true) {
            try {

                Socket s = ss.accept();
                DataInputStream dis = new DataInputStream(s.getInputStream());
                DataOutputStream dos = new DataOutputStream(s.getOutputStream());

                //read user
                String userHash = dis.readUTF();

                System.out.println("\nlogin from user: "+userHash);

                List<Message> userMessages = messagesMap.getOrDefault(userHash, new CopyOnWriteArrayList<>());
                if(!userMessages.isEmpty()) {
                    dos.writeBoolean(true);
                    int x = userMessages.size();
                    System.out.println("Delivering " + String.valueOf(x) + " message(s)");
                    dos.writeInt(x);

                    for (int a =0 ;a<x; a++) {
                       Message m1 = userMessages.remove(0);

                       dos.writeInt(m1.signature.length);
                       dos.write(m1.signature);

                       dos.writeInt(m1.message.length);
                       dos.write(m1.message);

                       dos.writeUTF(m1.date);
                    }
                }else {
                     dos.writeBoolean(false);
                 }

                boolean message = dis.readBoolean();
                if (message){
                    System.out.println("incoming message from " + dis.readUTF());
                }

                String dateString = dis.readUTF();
                int siglength = dis.readInt();
                byte[] signature = new byte[siglength];
                dis.readFully(signature);
                int length = dis.readInt();
                byte[] raw = new byte[length];
                dis.readFully(raw);

                //read server private key
                RSAPrivateKey prvKey = readPrivateKey("server");

                //decrypt senders message;
                byte[] msgBytes = DecrpytRSA(raw,prvKey);

                //read sender public key
                RSAPublicKey pubKey1 = readPublicKey(dis.readUTF());
                
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(pubKey1);
                sig.update(msgBytes);
                boolean b = sig.verify(signature);
                if(b) {
                    System.out.println("Signature Verififed");
                    dos.writeUTF("OK");
                }else{
                    System.out.println("Signature not verified");
                    dos.writeUTF("a");
                }

                String msg = new String(msgBytes, "UTF8");
                String[] split = msg.split(":");
                msg = split[0];
                String recipient = split[1];

                System.out.println("\nDate: " + dateString+ "\nMessage: " + msg +"\nRecipient: " + recipient);


                RSAPrivateKey srvKey = readPrivateKey("server");


                byte[]  ServerSig =generateSig(srvKey,msg.getBytes("UTF8") ) ;


                RSAPublicKey pubKey = readPublicKey(recipient);


                byte[] encyptedMsg = EncrpytRSA(msg.getBytes(), pubKey);


                String recipientHash = hash(recipient);


                Message m = new Message(encyptedMsg,dateString,ServerSig);
                messagesMap.computeIfAbsent(recipientHash,k-> new CopyOnWriteArrayList<>()).add(m);

            } catch (IOException e) {
                System.err.println("Client has closed the connection.");
                System.out.println("Awaiting new connection...");
            }
        }
    }

    private static RSAPublicKey readPublicKey(String userId){
        try{
            KeyFactory kf = KeyFactory.getInstance("RSA");
            File f = new File(userId+ ".pub");
            byte[] pubBytes = Files.readAllBytes(f.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
            return (RSAPublicKey) kf.generatePublic(pubSpec);
        } catch (Exception e) {
            System.err.println( "UserID not recognised");
        }
        return null;
    }
    private static byte[] DecrpytRSA(byte[] encryptedMsg, RSAPrivateKey privateKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] msgBytes = cipher.doFinal(encryptedMsg);
            return msgBytes;
        }catch (Exception e){
            return null;
        }
    }

    private static RSAPrivateKey readPrivateKey(String userId) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            File f = new File(userId + ".prv");
            byte[] prvBytes = Files.readAllBytes(f.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
            return (RSAPrivateKey) kf.generatePrivate(prvSpec);

        } catch (Exception e) {
            System.err.println( "UserID not recognised");
            return null;
        }

    }
    private static byte[] EncrpytRSA(byte[] msgBytes,RSAPublicKey publicKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] encrytedMsg = cipher.doFinal(msgBytes);
            return encrytedMsg;
        }catch (Exception e){
            return null;
        }}

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
    private static byte[] generateSig(RSAPrivateKey privateKey, byte[] messageBytes){
        try{
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(messageBytes);
            return sig.sign();
        }catch(Exception e) {
            System.out.println("error");
            return null;
        }
    }
}