package task1;

import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

public class NumberByHash {

  public static void main(String[] args) throws Exception {
    // Have a classmate calculate the sha-256 hash of a random number from
    // 1-1000 and give you the hex-encoded hash. Write a program that
    // finds the number given its hash (use brute force).

    // Hint: encode the number using the method below

    // TODO: implement
    System.out.println("my hash: " + Hex.encodeHexString(sha256(numberToBytes(666))));

    String hashToBreak = "60ee8841eafb9a52c849a9396c527830f674d2bb37d13d34f00e0ae54250cf25";
    byte[] target = Hex.decodeHex(hashToBreak);
    for (int i = 0; i <= 1000; i++) {
      byte[] candidate = sha256(numberToBytes(i));
      if (Arrays.equals(target, candidate)) {
        System.out.println("number was " + i);
        break;
      }
    }
  }

  static byte[] numberToBytes(int num) {
    return ByteBuffer.allocate(4).putInt(num).array();
  }

  static byte[] sha256(byte[] input) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(input);
  }
}
