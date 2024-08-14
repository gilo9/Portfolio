package org.example;
import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.nio.file.*;



public class encryption {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        if (args.length != 1) {System.err.println("Please choose a valid mode.");}
        if (args[0].equals("-e")) {
            //input
            System.out.println("Enter a message:");
            Scanner sc = new Scanner(System.in);
            String msg = sc.nextLine();
            sc.close();

            //key creation and file store
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            kg.init(new SecureRandom());
            SecretKey key= kg.generateKey();
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("secret.key"));
            out.writeObject(key);
            out.close();

            //encrpyt
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] emes= cipher.doFinal(msg.getBytes());
            //write to file
            FileOutputStream fos= new FileOutputStream("encrypted.msg");
            fos.write(emes);
            //fos.close();

        } else if (args[0].equals("-d")) {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("secret.key"));
        SecretKey key = (SecretKey)in.readObject();

        FileInputStream fis = new FileInputStream("encrypted.msg");
        byte[] raw = fis.readAllBytes();

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        byte[] msgBytes= cipher.doFinal(raw);
        String msg = new String(msgBytes,"UTF8");
        System.out.println(msg);
        }
        else{
            System.err.println("Please choose a valid mode");
        }
    }
    }
