import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        Scanner scanner = new Scanner(System.in);

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        String saltString = Base64.getEncoder().encodeToString(salt);
        saltString = "Cbm1NimMH4aHBQTRq1HKiQ==";
        salt = Base64.getDecoder().decode(saltString);
        System.out.print("Enter the key: ");
        String keyString = scanner.nextLine();

        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte [] encoded = sharedKey.getEncoded();

        System.out.print("Encrypt or decrypt a message? (e|d)");
        String option = scanner.nextLine();
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");
        if (option.equals("e")) {
            System.out.print("Enter message to encrypt: ");
            String message = scanner.nextLine();
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte [] encryptedData = cipher.doFinal(message.getBytes());
            String messageString = new String(Base64.getEncoder().encode(encryptedData));
            System.out.println(messageString);
        }
        else if (option.equals("d")) {
            System.out.print("Enter message to decrypt: ");
            String message = scanner.nextLine();
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte [] decoded = Base64.getDecoder().decode(message);
            byte [] decrypted = cipher.doFinal(decoded);
            message = new String(decrypted);
            System.out.println("Decrypted Message: " + message);
// 0IPw8Unj2gxTCjBTHqCUZw==
        }
        else {
            System.err.println("Wrong option");
            System.exit(1);
        }
    }
}