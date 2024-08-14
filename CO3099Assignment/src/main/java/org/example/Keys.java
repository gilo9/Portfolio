package org.example;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;

public class Keys {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        KeyGenerator kg =KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom());
        SecretKey key = kg.generateKey();

        byte[] b= key.getEncoded();

        StringBuilder sb = new StringBuilder();
        for (byte a:b) sb.append(String.format("%02X",a));
        System.out.println(Arrays.toString(b));
        System.out.println(sb.toString());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey r = (RSAPublicKey)kp.getPublic();
        RSAPrivateKey s = (RSAPrivateKey)kp.getPrivate();

       // System.out.println("modulus:" + r.getModulus());
        //System.out.println("public key component:" + r.getPublicExponent());
        //System.out.println("private key component:" + s.getPrivateExponent());

        File f = new File("C:\\Users\\grape\\OneDrive\\Documents\\Work\\Personal Projects\\CO3099Assignment\\src\\main\\java\\org\\example\\alice.prv");
        byte[] prvBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(prvBytes);

        File f1 = new File("C:\\Users\\grape\\OneDrive\\Documents\\Work\\Personal Projects\\CO3099Assignment\\src\\main\\java\\org\\example\\alice.pub");
        byte[] pubBytes = Files.readAllBytes(f1.toPath());
        X509EncodedKeySpec spec1 = new X509EncodedKeySpec(pubBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey prvKey = (RSAPrivateKey)kf.generatePrivate(spec);
        RSAPublicKey pubKey = (RSAPublicKey)kf.generatePublic(spec1);

        System.out.println("modulus:" + pubKey.getModulus());
        System.out.println("public key component:" + pubKey.getPublicExponent());
        System.out.println("private key component:" + prvKey.getPrivateExponent());


    }
}
