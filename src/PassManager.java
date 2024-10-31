import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;

public class PassManager {
    private static final int MAX_PASSWORD_LENGTH = 10; // Configurable length
    private static final String PLAINTEXT_FILE = "plaintext.txt";
    private static final String HASHED_FILE = "hash.txt";
    private static final String SALTED_FILE = "salt.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Welcome to the Password Manager!");
        System.out.println("Would you like to create an account or Log in?");
        System.out.print("Enter '1' to create an account or '2' to log in: ");
        String choice = scanner.nextLine().trim().toLowerCase();

        if (choice.equals("1")) {
            createAccount(scanner);
        } else if (choice.equals("2")) {
            authenticate(scanner);
        } else {
            System.out.println("Invalid choice. Exiting.");
        }

        scanner.close();
    }

    private static void createAccount(Scanner scanner) {
        String username = "";
        String password = "";
        
        while (true) {
            System.out.print("Enter a username (up to 10 alphabetic characters): ");
            username = scanner.nextLine().trim();
            if (validateUsername(username)) {
                break;
            } else {
                System.out.println("Invalid username. It must be up to 10 alphabetic characters.");
            }
        }

        while (true) {
            System.out.print("Enter a password (up to " + MAX_PASSWORD_LENGTH + " lowercase letters): ");
            password = scanner.nextLine().trim();
            if (validatePassword(password)) {
                break;
            } else {
                System.out.println("Invalid password. It must be up to " + MAX_PASSWORD_LENGTH + " lowercase letters (a-z).");
            }
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(PLAINTEXT_FILE, true))) {
            writer.write(username + ":" + password);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Error writing to " + PLAINTEXT_FILE);
        }

        String hashedPassword = hash(password);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(HASHED_FILE, true))) {
            writer.write(username + ":" + hashedPassword);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Error writing to " + HASHED_FILE);
        }


        byte saltByte = (byte) new Random().nextInt(256);
        String salt = String.format("%02x", saltByte);


        String saltedHash = hash(password + salt);


        try (BufferedWriter writer = new BufferedWriter(new FileWriter(SALTED_FILE, true))) {
            writer.write(username + ":" + salt + ":" + saltedHash);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Error writing to " + SALTED_FILE);
        }

        System.out.println("Account created");
    }

    private static void authenticate(Scanner scanner) {
        System.out.print("Enter your username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Enter your password: ");
        String password = scanner.nextLine().trim();


        boolean plaintextAuth = authenticatePlaintext(username, password);
        boolean hashedAuth = authenticateHashed(username, password);
        boolean saltedAuth = authenticateSalted(username, password);


        System.out.println("Plaintext verified: " + (plaintextAuth ? "Success" : "Failure"));
        System.out.println("Hash verified: " + (hashedAuth ? "Success" : "Failure"));
        System.out.println("Salt verified: " + (saltedAuth ? "Success" : "Failure"));
    }

    private static boolean validateUsername(String username) {
        if (username.length() > 10) {
            return false;
        }
        return username.matches("[A-Za-z]+");
    }

    private static boolean validatePassword(String password) {
        if (password.length() > MAX_PASSWORD_LENGTH) {
            return false;
        }
        return password.matches("[a-z]+");
    }

    private static String hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, digest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean authenticatePlaintext(String username, String password) {
        try (BufferedReader reader = new BufferedReader(new FileReader(PLAINTEXT_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String fileUsername = parts[0];
                    String filePassword = parts[1];
                    if (fileUsername.equals(username) && filePassword.equals(password)) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading from " + PLAINTEXT_FILE);
        }
        return false;
    }

    private static boolean authenticateHashed(String username, String password) {
        try (BufferedReader reader = new BufferedReader(new FileReader(HASHED_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String fileUsername = parts[0];
                    String fileHashedPassword = parts[1];
                    if (fileUsername.equals(username)) {
                        String inputHashedPassword = hash(password);
                        if (fileHashedPassword.equals(inputHashedPassword)) {
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading from " + HASHED_FILE);
        }
        return false;
    }

    private static boolean authenticateSalted(String username, String password) {
        try (BufferedReader reader = new BufferedReader(new FileReader(SALTED_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":", 3);
                if (parts.length == 3) {
                    String fileUsername = parts[0];
                    String fileSalt = parts[1];
                    String fileSaltedHash = parts[2];
                    if (fileUsername.equals(username)) {
                        String inputSaltedHash = hash(password + fileSalt);
                        if (fileSaltedHash.equals(inputSaltedHash)) {
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading from " + SALTED_FILE);
        }
        return false;
    }
}
