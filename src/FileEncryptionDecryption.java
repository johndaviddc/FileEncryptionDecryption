import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;

public class FileEncryptionDecryption {

    private static SecretKeySpec generateKey(String password) throws Exception {
        byte[] keyBytes = password.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        keyBytes = sha.digest(keyBytes);
        keyBytes = Arrays.copyOf(keyBytes, 16);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        SecretKeySpec secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBytes = new byte[(int) new File(inputFile).length()];
            inputStream.read(inputBytes);

            byte[] encryptedBytes = cipher.doFinal(inputBytes);
            outputStream.write(encryptedBytes);
        }
    }

    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        SecretKeySpec secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBytes = new byte[(int) new File(inputFile).length()];
            inputStream.read(inputBytes);

            byte[] decryptedBytes = cipher.doFinal(inputBytes);
            outputStream.write(decryptedBytes);
        }
    }

    public static void main(String[] args) {
        String inputFile = "input.txt";
        String encryptedFile = "encrypted.enc";
        String decryptedFile = "decrypted.txt";
        String password = "supersecretpassword";

        try {
            encryptFile(inputFile, encryptedFile, password);
            System.out.println("File encrypted successfully!");

            decryptFile(encryptedFile, decryptedFile, password);
            System.out.println("File decrypted successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}