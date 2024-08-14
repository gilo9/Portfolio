package org.example;

import java.io.*;

class streams {

    public static void main(String [] args) throws Exception {


        System.out.println("Please type a line:");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String y = br.readLine();
        int x = Integer.parseInt(br.readLine());

       FileOutputStream f = new FileOutputStream("somefile");
       DataOutputStream out = new DataOutputStream(f);

        out.writeUTF(y);
        out.writeInt(x);
        out.flush();

        FileInputStream f1 = new FileInputStream("somefile");
        DataInputStream d = new DataInputStream(f1);
        String z = d.readUTF();
        int w = d.readInt();
        System.out.println(z);
        System.out.println(w);
    }
}