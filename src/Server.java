import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    static Cipher dcipher;
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

    public static void main(String[] args) {
        try(ServerSocket serverSocket = new ServerSocket(8080)){

            System.out.println("listening port : 8080");

            Socket clientSocket = serverSocket.accept();

            System.out.println(clientSocket+" Connection Established.");

            dataInputStream = new DataInputStream(clientSocket.getInputStream());

            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            receiveFile();

            dataInputStream.close();
            dataOutputStream.close();
            clientSocket.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    private static void PGP(String data, String hash, String key) throws Exception
    {
        String[] message={data,hash,key};        // public keyi dosyadan çekmeye yarıyor.
        byte[] bytes = Files.readAllBytes(Paths.get("Public.pub"));
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(ks);

        byte[] bytes2 = Files.readAllBytes(Paths.get("Private.key"));       //private keyi çekmeye yarıyor
        PKCS8EncodedKeySpec ks2 = new PKCS8EncodedKeySpec(bytes2);
        KeyFactory kf2 = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf2.generatePrivate(ks2);


        byte[] encrypted=Base64.getDecoder().decode(key);       //receiver senderda yolladıgımız encrypted keyi private key ile decryptliyor.
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] utf8 = cipher.doFinal(encrypted);
        String eRecevierSecretKey=new String(utf8,"UTF8");
        byte[] dReceiverSecretKey = Base64.getDecoder().decode(eRecevierSecretKey);
        SecretKey originalKey = new SecretKeySpec(dReceiverSecretKey, 0, dReceiverSecretKey.length, "DES");
        String receiverdEcryptedMessage[] = new String[message.length-1];

        dcipher = Cipher.getInstance("DES");                //desin tamamen acilmis hali
        dcipher.init(Cipher.DECRYPT_MODE, originalKey);
        for(int i=0;i<message.length-1;i++)
        {
            byte[] dec=Base64.getDecoder().decode(message[i]);         //burda tamamen mesajı decryptliyoruz
            byte[] utf8_ = dcipher.doFinal(dec);
            message[i]= new String(utf8_,"UTF8");
        }
        String unzippedString[]=new String[receiverdEcryptedMessage.length];

        File fout = new File("Decrypted.txt");
        FileOutputStream fos = new FileOutputStream(fout);

        for(int i=0;i<unzippedString.length;i++)   // burda mesajı unzipliyoruz.
        {
            byte[] compressed=Base64.getDecoder().decode(message[i]);
            ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
            GZIPInputStream gis = new GZIPInputStream(bis);
            BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;

            while((line = br.readLine()) != null) {
                if(i==0)
                {
                    fos.write(line.getBytes("utf8"));   // mesajı dosyaya yazmak icin
                    fos.write(10);

                }
                sb.append(line);
            }
            fos.close();
            br.close();
            gis.close();
            bis.close();
            unzippedString[i]=sb.toString();

        }

        byte[] encrypted2=Base64.getDecoder().decode(unzippedString[1]);
        cipher.init(Cipher.DECRYPT_MODE,publicKey);             // hashi publickey ile decryptliyor
        byte[] utf8_2 = cipher.doFinal(encrypted2);
        String receivedHash=new String(utf8_2,"UTF8");

        MessageDigest digest = MessageDigest.getInstance("SHA-512");            // encrypted hashi ayırdık
        digest.reset();
        digest.update(unzippedString[0].getBytes("utf8"));
        String calculatedHash = String.format("%040x", new BigInteger(1, digest.digest()));

        // burda hashleri kontrol edebliliyoruz.
        if(receivedHash.equals(calculatedHash))
        {
            System.out.println("Hashes are equal !\n");
        }

    }

    private static void receiveFile() throws Exception{           // fileı karşıdan çekmek için

        int length=dataInputStream.readInt();
        byte[] data_=new byte[length];
        dataInputStream.readFully(data_);
        String data =new String(data_,"UTF-8");

        System.out.println(data+"\n\n");


        int length2=dataInputStream.readInt();
        byte[] hash_=new byte[length2];
        dataInputStream.readFully(hash_);
        String hash=new String(hash_,"UTF-8");

        System.out.println(hash+"\n\n");

        int length3=dataInputStream.readInt();
        byte[] key_=new byte[length3];
        dataInputStream.readFully(key_);
        String key=new String(key_,"UTF-8");

        PGP(data,hash,key);

    }
}