package org.example;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class bytes {
    public static void main(String[] args) throws UnsupportedEncodingException {
        byte[] b = {0x12, 0x34, 0x56, 0x78, (byte)0x9A, (byte)0xBC, (byte)0xDE, (byte)0xF0};
        String s= new String(b,"UTF8");
        StringBuilder sb = new StringBuilder();
        for (byte a:b) sb.append(String.format("%02X",a));
        System.out.println(sb.toString());
    }
}
