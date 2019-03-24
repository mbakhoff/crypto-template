package task5;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

public class EncryptionApp {

  private static final SecureRandom rng = new SecureRandom();

  public static void main(String[] args) throws Exception {
    // Write a program that takes a mode string ("encrypt" or "decrypt"),
    // two filenames (input and output) and a password as command line
    // arguments. The program should encrypt or decrypt the input file
    // depending on the specified mode. Generate the key from the
    // password using PBKDF2, store the salt, iterations and IV with
    // the encrypted data (in the beginning or end of the file).

    // Hint: use InputStream#readNBytes to read the stored salt and IV

    // TODO: implement
    String mode = args[0];
    Path file = Path.of(args[1]);
    String password = args[2];

    if (mode.equalsIgnoreCase("encrypt")) {
      encrypt(file, password);
    } else if (mode.equalsIgnoreCase("decrypt")) {
      decrypt(file, password);
    } else {
      throw new IllegalArgumentException("unsupported mode " + mode);
    }
  }

  private static void encrypt(Path file, String password) throws Exception {
    // key from password
    byte[] salt = new byte[32];
    rng.nextBytes(salt);
    int iterationCount = 500_000;
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, 256);
    byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();

    // encryption
    byte[] data = Files.readAllBytes(file);
    byte[] iv = new byte[12];
    rng.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, iv));
    byte[] encrypted = cipher.doFinal(data);

    // output
    // this overwrites the original file
    // it's also ok to write the encrypted version to another file
    try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(file))) {
      dos.writeInt(iterationCount);
      dos.write(salt);
      dos.write(iv);
      dos.writeInt(encrypted.length);
      dos.write(encrypted);
    }
  }

  private static void decrypt(Path file, String password) throws Exception {
    // input
    int iterationCount;
    byte[] salt;
    byte[] iv;
    byte[] encrypted;
    try (DataInputStream dis = new DataInputStream(Files.newInputStream(file))) {
      iterationCount = dis.readInt();
      salt = dis.readNBytes(32);
      iv = dis.readNBytes(12);
      int encryptedLength = dis.readInt();
      encrypted = dis.readNBytes(encryptedLength);
    }

    // key from password
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, 256);
    byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();

    // decryption
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, iv));
    byte[] data = cipher.doFinal(encrypted);

    // output
    Files.write(file, data);
  }
}
