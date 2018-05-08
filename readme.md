# Crypto basics

Cryptographic algorithms enable protection of sensitive data.
Different algorithms provide different security properties:

* confidentiality - unauthorized parties cannot access the data
* integrity - unauthorized parties cannot modify the data undetected
* authenticity - the source of the data can be verified

## Hashing

*A cryptographic hash function is a mathematical algorithm that maps data of arbitrary size to a bit string of a fixed size (a hash) and is designed to be a one-way function, that is, a function which is infeasible to invert.* - Wikipedia

This is how hashing data in Java looks like:
```
import java.security.MessageDigest;

byte[] sha256(byte[] input) throws Exception {
  return MessageDigest.getInstance("SHA-256").digest(input);
}
```

A cryptographic hash function has the following properies:
* same input always results in the same output
* small change in the input causes an extensive change in the output
* infeasible to find the input value based on just the output value
* infeasible to find two different inputs with the same output

The sample above uses the **SHA-256** hash function.
It will transform the input into a seemingly random `byte[]` of 32 bytes (256 bits).
Other hash functions may have different output sizes, e.g. output of the MD5 function is 16 bytes.

Some examples of using hashes:
* The [download page of Apache Maven](https://maven.apache.org/download.cgi) lists the sha256 hash for each maven installer zip.
  Maven can be downloaded from servers all over the world (see [complete list of mirrors](https://www.apache.org/mirrors/)), not all of which are under Maven's control.
  The user can download the installer zip from any mirror, hash the downloaded file and compare the hash with the one published on maven's website.
  If the hash doesn't match, then the file has been corrupted/modified.
* Hashing can be used to generate a (practically) unique id for a file based on its content.
  The Git version control system uses the hash of the file changes to generate the commit id.

The output of the hash function is a `byte[]`.
This can be a bit inconvenient to work with, so it's common to see the hash as a hex encoded string:

```
import org.apache.commons.codec.binary.Hex;

byte[] hash = sha256(something);
String encoded = Hex.encodeHexString(hash);
byte[] decoded = Hex.decodeHex(encoded);

// the string looks something like this:
// af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf
```

## Storing passwords securely

Passwords should not be stored on disk as plain text for any reason, ever.
All programs have bugs, too many systems are hacked every day and most users reuse their passwords across different systems.

The right way to store a password is to hash it and store only the hash.
When the user later logs in, the password can be hashed again and compared with the stored value.
However, not all hash functions are suitable for passwords.

The problem with passwords is that they are usually either short or use dictionary words.
Imagine that the users' passwords are stored in a database as SHA-256 hashes.
When an attacker gains access to the database, then they cannot see the original password and they cannot reverse the hash function to learn the original password (hash functions are one-way).
However, the attacker can try all possible password combinations and find the one that matches the stored hash (**brute force attack**).

The main issue is that most hash functions are designed to be fast.
A hundred GPUs rented from the cloud can calculate literally billions of hashes a second.
Functions with specific properties have been built for hashing passwords:
* slow to compute
* higher memory usage
* difficult to optimize with special-purpose hardware

Good hash function choices for storing passwords are: **bcrypt**, scrypt, argon2 and **PBKDF2**.
General purpose fast hash functions, such as md5/sha1/sha256 should not be used.

## PBKDF2

**PBKDF2** (Password-Based Key Derivation Function 2) is a function that can transform passwords into secure password hashes or encryption keys.
PBKDF2 works by combining the password with a random string (**salt**) and applying a general purpose hash function multiple times (**iteration count**).

The higher the iteration count, the slower the PBKDF2 function becomes.
The slower the function is, the harder it is to find the password by trying all possible combinations.
The iteration count can be chosen so that calculating the function takes around 500ms on a local machine, which should be secure enough for most use cases.

Why is the salt needed?
Most passwords are short (1-8 characters).
If there was no salt, then an attacker could calculate the PBKDF2 function for each possible password of length 1-8 and store the results in a table.
Calculating such a table (called a *rainbow table*) would take quite a bit of time as a one-time investment.
After that, the table could be used to look up any password by its PBKDF2 value in a millisecond.
The salt simply makes the passwords longer.
A table of hashes for all alpha-numeric passwords of length 1-8 takes [around 127GB](http://project-rainbowcrack.com/table.htm).
Adding a salt of 8 additional characters would increase the table size to impossible.

Steps for using PBKDF2 for password hashing:
1. choose an iteration count
2. generate a random salt for the password (don't reuse the salt for different passwords)
3. calculate the key using PBKDF2
4. store the user id, key, salt and iteration count in a file/database

```
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

String password = <provided by user>;

// choose the iteration count
int iterationCount = 1_000_000;

// generate the salt
SecureRandom rng = new SecureRandom();
byte[] salt = new byte[32];
rng.nextBytes(salt);

// output length of SHA-256
int outputLengthBits = 256;

PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, outputLengthBits);
byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
```

Steps for verifying the password at login:
1. find the stored key, salt and iteration count by user id
3. calculate PBKDF2 using the stored salt and iteration count
3. compare the calculated key and the stored key (should match)

Note that the salt is not a secret.
Its only purpose is to make building rainbow tables more difficult.

## HMAC

Imagine that you need to send a file over an insecure network and verify that an attacker has not modified the file during the transfer.

One way is to hash the file before sending it and check that the hash of the transferred file matches the original hash.
However, this only works if the hash can be transferred in a secure way.
If the hash is also transferred using the insecure network, then an attacker could modify the file, hash it and replace both the file and the transferred hash.

The solution is to use HMAC instead of a regular hash function.
**HMAC** (hash-based message authentication code) is similar to a regular hash function, but the output also depends on a key specified when creating the hash.
The key can either be some random bytes or a key produced from a password using PBKDF2.

Computing a HMAC in Java:
```
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

byte[] hmac(byte[] data, byte[] key) throws Exception {
  Mac mac = Mac.getInstance("HmacSHA256");
  mac.init(new SecretKeySpec(key, "HmacSHA256"));
  return mac.doFinal(data);
}
```

If both the sender and the receiver of the file have shared a password using some secure channel, then HMAC can be used to secure a file transfer even over an insecure network:

On the sender side:
* create a key from the password using PBKDF2
* calculate the HMAC of the file
* send the file, the HMAC and the PBKDF2 parameters (salt, iterations)

On the receiver side:
* calculate the key using the PBKDF2 parameters from the sender
* calculate the HMAC from the file
* check that the HMAC matches

When multiple files need to be transferred at once, then the key can be reused for all of them.

HMAC is as secure as secure as the key that is used.
PBKDF2 is a good way to generate a secure key, but it's not the only option.
The sender and the receiver could just as well find a way to securely share some random bytes and use these as the key.

## AES

The previous algorithms have only helped to ensure that an attacker cannot modify some data without being detected.
Often it's also useful to encrypt data, i.e. make it unreadable to anyone who doesn't have the right key.
Encryption can be used for both transferring data or for long term storage on the disk.

A good encryption algorithm has the following properties:
* encrypted data is indistinguishable from random bytes
* encrypted data can be decrypted using only the right key
* encrypting the same file with the same key multiple times should result in a different output each time.
  comparing different encrypted files should not reveal their content.

The exact process of encrypting a file depends on the encryption algorithm (the cipher).
The samples here will be using the **AES** cipher in GCM mode.

Encrypting a file in Java:
```
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

// bytes to be encrypted
byte[] data;

// a 32 byte key (randomly generated or from PBKDF2)
byte[] key;

// generate the IV (initialization vector, see below)
SecureRandom rng = new SecureRandom();
byte iv[] = new byte[12];
rng.nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE,
  new SecretKeySpec(key, "AES"),
  new GCMParameterSpec(128, iv));
byte[] encrypted = cipher.doFinal(data);
```

Some notes:
* The initialization vector (IV) is some random bytes.
  It is critical that an unique IV is generated for each encrypted file.
  Using an unique IV ensures that encrypting the sama data results in a different output each time.
  The value of the IV is not a secret and it is needed later to decrypt the data.
* The recommended key size for AES is 256-bit (32 bytes).
  The encryption is as strong as the key.
  Generate a strong key using SecureRandom or use PBKDF2 on a string password.
* AES/GCM has a built-in authentication tag that works similar to a HMAC.
  The magic value 128 passed to the GCMParameterSpec constructor specifies the tag size (in bits).

Decryption is similar to the encryption in Java:
```
// bytes to be decrypted
byte[] encrypted;

// the key and iv that were used for encryption
byte[] key;
byte iv[];

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.DECRYPT_MODE,
  new SecretKeySpec(key, "AES"),
  new GCMParameterSpec(128, iv));
byte[] data = cipher.doFinal(encrypted);
```

Note that AES is not the only cipher and GCM is not the only mode.
Other ciphers and modes have different security properties.
Cryptography is a minefield.
Don't try to build your own cipher and consult with an expert when choosing a new cipher for your project.

## Going forward

This tutorial only covered the basics of symmetric cryptography (the same key is used for encryption and decryption).
There also exists asymmetric cryptography, where a different key is used for encryption/decryption.
This is used for digital signatures, setting up HTTPS connections etc.

## Tasks

1. Have a classmate calculate the hash of a random number from 1-1000 and give you the hash.
   Write a program that finds the number given its hash (use brute force).
2. Pick a random password and hash it with `PBKDF2WithHmacSHA256`.
   Find the iteration count that takes ~500ms on your machine.
3. Write a program that takes two file names as command line arguments.
   The program should calculate the HMAC of the first file using the key in the second file and output the hex encoded result.
   Generate a file that contains 32 random bytes (for using as a key) and test the program.
4. Write a program that takes a mode string ("encrypt" or "decrypt"), a filename and a password as command line arguments.
   The program should encrypt or decrypt the given file depending on the specified mode.
   Generate the key from the password using PBKDF2, store the salt, iterations and IV with the encrypted data (in the beginning or end of the file).
