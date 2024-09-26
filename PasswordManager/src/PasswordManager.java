import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PasswordManager {

    // Global Constants
    private static final String FILE_NAME = "passwords.txt";
    private static final int ITERATIONS = 600000;
    private static final int KEY_LENGTH = 128;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        Map<String, String> passwordData = new HashMap<>();

        File passwordFile = new File(FILE_NAME);
        byte[] salt;
        byte[] encryptedToken;

        // Step 1: Check if password file exists
        if (!passwordFile.exists()) {
            // Create new password file
            System.out.print("Enter the passcode to create the password manager: ");
            String masterPassword = scanner.nextLine();

            // Generate salt
            salt = generateSalt();
            // Create and encrypt token for future verification
            encryptedToken = encryptToken(masterPassword, salt);
            saveToFile(passwordData, salt, encryptedToken);
            System.out.println("No password file detected. Creating a new password file.");
        } else {
            // Step 2: If file exists, verify password
            System.out.print("Enter the passcode to access your passwords: ");
            String masterPassword = scanner.nextLine();

            // Load the salt and token
            passwordData = loadFromFile();
            salt = Base64.getDecoder().decode(passwordData.get("salt"));
            encryptedToken = Base64.getDecoder().decode(passwordData.get("token"));

            // Verify the master password
            if (!verifyToken(masterPassword, salt, encryptedToken)) {
                System.err.println("Incorrect password! Exiting.");
                System.exit(1);
            }
        }

        // Step 3: User menu for adding or reading passwords
        while (true) {
            System.out.println("a : Add Password\nr : Read Password\nq : Quit");
            System.out.print("Enter choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "a":
                    // Add password
                    addPassword(scanner, passwordData, salt);
                    saveToFile(passwordData, salt, encryptedToken);
                    break;
                case "r":
                    // Read password
                    readPassword(scanner, passwordData, salt);
                    break;
                case "q":
                    System.out.println("Quitting");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice.");
                    break;
            }
        }
    }

    // Generate a random salt
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // Encrypt the token for password verification
    private static byte[] encryptToken(String password, byte[] salt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(password, salt);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        String token = "verify";  // Static token to verify password later
        return cipher.doFinal(token.getBytes());
    }

    // Verify if the password entered is correct
    private static boolean verifyToken(String password, byte[] salt, byte[] encryptedToken) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(password, salt);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedToken = cipher.doFinal(encryptedToken);
        return new String(decryptedToken).equals("verify");
    }

    // Derive AES key from password and salt using PBKDF2
    private static SecretKeySpec deriveKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    // Add a password to the password manager
    private static void addPassword(Scanner scanner, Map<String, String> passwordData, byte[] salt) throws Exception {
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();
        System.out.print("Enter password to store: ");
        String password = scanner.nextLine();

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(label, salt);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());
        passwordData.put(label, Base64.getEncoder().encodeToString(encryptedPassword));
    }

    // Read a password from the password manager
    private static void readPassword(Scanner scanner, Map<String, String> passwordData, byte[] salt) throws Exception {
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();

        String encryptedPassword = passwordData.get(label);
        if (encryptedPassword == null) {
            System.out.println("Password not found for label: " + label);
            return;
        }

        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(label, salt);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedPassword = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        System.out.println("Found: " + new String(decryptedPassword));
    }

    // Save the salt and encrypted token, along with password data to the file
    private static void saveToFile(Map<String, String> passwordData, byte[] salt, byte[] encryptedToken) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME));
        writer.write(Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(encryptedToken) + "\n");

        for (Map.Entry<String, String> entry : passwordData.entrySet()) {
            if (!entry.getKey().equals("salt") && !entry.getKey().equals("token")) {
                writer.write(entry.getKey() + ":" + entry.getValue() + "\n");
            }
        }

        writer.close();
    }

    // Load the salt, token, and encrypted passwords from the file
    private static Map<String, String> loadFromFile() throws IOException {
        Map<String, String> passwordData = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            passwordData.put(parts[0], parts[1]);
        }
        reader.close();
        return passwordData;
    }
}

