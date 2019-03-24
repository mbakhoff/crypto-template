package task1;

import java.nio.ByteBuffer;

public class NumberByHash {

  public static void main(String[] args) throws Exception {
    // Have a classmate calculate the sha-256 hash of a random number from
    // 1-1000 and give you the hex-encoded hash. Write a program that
    // finds the number given its hash (use brute force).

    // Hint: encode the number using the method below

    // TODO: implement
  }

  static byte[] numberToBytes(int num) {
    return ByteBuffer.allocate(4).putInt(num).array();
  }
}
