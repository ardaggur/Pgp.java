import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.swing.*;
import java.util.*;
import java.math.*;
import javax.crypto.Cipher;
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPOutputStream;

public class Client {
    static Cipher ecipher;
    static JFrame jFrame;
    static JLabel jLabel;
    static JButton jButton;
    static JTextField textField;
    static JPanel jPanel;
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

    public static void main(String[] args) {

        jFrame = new JFrame("Client Server File Transfer Application");
        jLabel = new JLabel("Enter the path of the file: ");
        jButton = new JButton("Send");
        jButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e) {

                String s = textField.getText();
                chooseFile(s);
            }

        });
        textField = new JTextField(15);
        jPanel = new JPanel();
        jPanel.setBounds(0, 75, 300, 250);
        jPanel.add(textField);
        jPanel.add(jButton);
        jPanel.add(jLabel);
        jFrame.add(jPanel);
        jFrame.setSize(350, 300);
        jFrame.setLayout(null);
        jFrame.setVisible(true);


    }

    public static void PGP(String path) throws Exception
    {


        String input = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator2.initialize(2048);
        KeyPair keyPair1=keyPairGenerator.genKeyPair();
        KeyPair keyPair2=keyPairGenerator.genKeyPair();
        PrivateKey senderPrivateKey =  keyPair1.getPrivate();
        PublicKey receiverPubKey =  keyPair2.getPublic();



        try (FileOutputStream out = new FileOutputStream("private.key")) {
            out.write(keyPair2.getPrivate().getEncoded());
        }

        try (FileOutputStream out = new FileOutputStream("public.pub")) {
            out.write(keyPair1.getPublic().getEncoded() );
        }

        String hashout ="";
        MessageDigest digest=MessageDigest.getInstance("SHA-512");
        digest.reset();
        digest.update(input.getBytes("utf8"));
        hashout = String.format("%040x", new BigInteger(1, digest.digest()));

        Cipher cipher = Cipher.getInstance("RSA");  //sender private key kullanarak hashi encryptliyor
        cipher.init(Cipher.ENCRYPT_MODE,senderPrivateKey);
        byte[] utf8 =cipher.doFinal(hashout.getBytes("UTF-8"));
        String encryptedPrivateHash= Base64.getEncoder().encodeToString(utf8);

        String beforeZip[]={input,encryptedPrivateHash};      //input ve encrypted hashi zipledim.
        String afterZip[]=new String[beforeZip.length];
        for(int i=0;i<beforeZip.length;i++)
        {
            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream(beforeZip[i].length());
            GZIPOutputStream gZip=new GZIPOutputStream(byteArrayOutputStream);
            gZip.write(beforeZip[i].getBytes());
            gZip.close();
            byte[] compressed=byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
            afterZip[i]=Base64.getEncoder().encodeToString(compressed);
        }

        SecretKey key=KeyGenerator.getInstance("DES").generateKey();           //zipi des ile secret key kullanarak encryptledim.
        String afterZipDES[]=new String[afterZip.length+1];
        for(int i=0;i<afterZip.length;i++)
        {
            ecipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] utf8str =afterZip[i].getBytes("UTF8");
            byte[] encrypted = ecipher.doFinal(utf8str);
            afterZipDES[i]=Base64.getEncoder().encodeToString(encrypted);
        }

        String encodedKey=Base64.getEncoder().encodeToString(key.getEncoded());     //receiver public key kullanarak des'in keyini ecryptledik
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.ENCRYPT_MODE, receiverPubKey);
        byte[] utf8new2 = cipher2.doFinal(encodedKey.getBytes("UTF-8"));
        String encryptedKey=Base64.getEncoder().encodeToString(utf8new2);

        afterZipDES[2]=encryptedKey;
        String messageToServer[]=afterZipDES;

        sendFile(messageToServer);
    }


    public static void chooseFile(String path)
    {
        try(Socket socket = new Socket("localhost",8080)) {
            dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());


            PGP(path);


            dataInputStream.close();

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    private static void sendFile(String array[]) throws Exception
    {

        byte[] data=array[0].getBytes("UTF-8");
        dataOutputStream.writeInt(data.length); // datanın lengthini buluyorsun
        dataOutputStream.write(data);      // onu lengthe gore gonderıyor

        byte[] hash=array[1].getBytes("UTF-8");
        dataOutputStream.writeInt(hash.length);
        dataOutputStream.write(hash);

        byte[] key=array[2].getBytes("UTF-8");
        dataOutputStream.writeInt(key.length);
        dataOutputStream.write(key);
    }
}