# Crypto basics

Cryptographic algorithms can be used to make sure bad people aren't listening in to your communication or changing their contents.
Modern crypto APIs are designed to be useful even without understanding the maths behind them completely.
Here we will look at the most commonly used tools for securing data and communications.

## Hashing

*A cryptographic hash function is a mathematical algorithm that maps data of arbitrary size to a bit string of a fixed size (a hash) and is designed to be a one-way function, that is, a function which is infeasible to invert.* - Wikipedia

Or simply put: hashing turns your data into a small unique string (hash).

A cryptographic hash function has the following properies:
* same input always results in the same output
* small change in the input causes an extensive change in the output
* very hard to find the input value based on just the output value
* very hard to find two different inputs with the same output

A hash can be used for many different things:
* a checksum
* a fingerprint / unique id for the source document
* an optimization for digital signatures
* storing passwords securely

Some examples of using hashes:
* The [download page of Apache Maven](https://maven.apache.org/download.cgi) lists the hash for each maven zip.
  Maven can be downloaded from servers all over the world (see [complete list of mirrors](https://www.apache.org/mirrors/)), not all of which are under Maven's control.
  The user can download the installer zip from any mirror, hash the downloaded file and compare the hash with the one published on maven's website.
  If the hash doesn't match, then the file has been corrupted/modified.
* Hashing can be used to generate a (practically) unique id for a file based on its content.
  The Git version control system uses the hash of the file changes to generate the commit id.
* When digitally signing a document with mobile-id, the phone actually only signs a hash of the document.
  This way the entire document (could be rather large) doesn't need to sent to the phone for signing.

This is how hashing data in Java looks like:
```
import java.security.MessageDigest;

byte[] sha256(byte[] input) throws Exception {
  return MessageDigest.getInstance("SHA-256").digest(input);
}
```

The sample above uses the **SHA-256** hash function.
It will transform the input into a seemingly random `byte[]` of 32 bytes (256 bits).
Other hash functions may have different output sizes, e.g. output of the (old and insecure) MD5 function is 16 bytes.
The output `byte[]` can be a bit inconvenient to work with, so it's common to see the hash as a hex encoded string:

```
import org.apache.commons.codec.binary.Hex;

byte[] hash = sha256(something);
String asString = Hex.encodeHexString(hash);
System.out.println(asString);
// af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf
byte[] sameHash = Hex.decodeHex(asString);
```

## Storing passwords securely

Users often use passwords to log in to services and the service needs to verify whether the password is correct.
A rookie mistake is to store the username-password pairs for all registered users.
That's a very naughty thing to do for multiple reasons:
* if your service gets hacked and the passwords are leaked, then the hacker can use the passwords to log in as any user
* users like to reuse their passwords, so the hacker can also log in to the user's accounts on other services

The solution is to **never store a password in plain-text**.
Instead, hash the password on registration and store only the hash.
When the user later logs in, the password can be hashed again and compared with the stored hash.
Hackers can't steal what you don't have.

Note that not all hash functions are suitable for passwords.
The problem with passwords is that they are usually either short or use dictionary words.
Imagine that the users' passwords are stored in a database as SHA-256 hashes.
When an attacker gains access to the database, then they cannot see the original password and they cannot reverse the hash function to learn the original password (hash functions are one-way).
However, the attacker can try all possible password combinations and find the one that matches the stored hash (**brute force attack**).
Most hash functions are designed to be fast and a hundred GPUs rented from the cloud can calculate literally billions of hashes per second.

To safely store a password, a specialized hash function should be used that is slow to compute, has high memory usage and cannot be optimized in hardware.
Currently the best option seems to be [argon2](https://password-hashing.net/).
Another popular option is the older PBKDF2 function.
General purpose fast hash functions (md5/sha1/sha256) should not be used for passwords.

Using argon2 in java is quite easy.
Add a maven dependency for [argon2-jvm](https://github.com/phxql/argon2-jvm).
The library provides two functions: `hash` and `verify`.

```
final Argon2 argon2 = Argon2Factory.create();

void register(String user, String password) {
  // parameters can be tweaked to make the hash slower / more secure
  String hash = argon2.hash(30, 65536, 1, password.toCharArray());
  saveUserAndHash(user, hash);
}

void login(String user, String password) {
  String hash = loadHashByUser(user);
  if (!argon2.verify(hash, password)) {
    throw new IllegalStateException("invalid password");
  }
}
```

## PBKDF2

Passwords are sometimes used to encrypt a file or a network stream.
Unfortunately, using the password itself as the key is not very secure.
People are not good at remembering long/complicated passwords and a short/dictionary-based password can be easily brute forced (try all combinations).

**PBKDF2** (Password-Based Key Derivation Function 2) is a function that can transform passwords into secure password hashes or encryption keys.
PBKDF2 works by combining the password with a random string (**salt**) and applying a general purpose hash function multiple times (**iteration count**).

Increasing the iteration count makes the function slower and more expensive to break with brute force.

Using the salt makes it possible to generate multiple encryption keys from a single password (new salt = new key).
Salt also helps to avoid [rainbow table attacks](https://en.wikipedia.org/wiki/Rainbow_table).

Generating an encryption key using PBKDF2:
1. choose an iteration count
2. generate a new random salt
3. calculate the key using PBKDF2
4. use the result to encrypt a file or store it in the database to later verify a password-based login.

Calculating PBKDF2 in Java:
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

// output length of SHA-256 (32 bytes)
int outputLengthBits = 256;

PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, outputLengthBits);
byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
```

Note that the salt and iteration count are not secret and can be stored in plain text where ever they are needed.

## Encryption

Sometimes it's useful to encrypt data, i.e. make it unreadable to anyone who doesn't have the right key.
Encryption can be used for both transferring data or for long term storage on the disk.

A good encryption algorithm has the following properties:
* encrypted data is indistinguishable from random bytes
* encrypted data can be decrypted using only the right key
* encrypting the same file with the same key multiple times should result in a different output each time.
  comparing different encrypted files should not reveal their content.

The exact process of encrypting a file depends on the encryption algorithm (the cipher).
The samples here will be using the **AES** cipher in [GCM mode](https://crypto.stackexchange.com/questions/17999/aes256-gcm-can-someone-explain-how-to-use-it-securely-ruby).

Encrypting a file in Java:
```
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

// bytes to be encrypted (plain text)
byte[] data;

// a 32 byte key (from PBKDF2 or randomly generated)
byte[] key;

// generate the IV (initialization vector, see below)
SecureRandom rng = new SecureRandom();
byte[] iv = new byte[12];
rng.nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE,
  new SecretKeySpec(key, "AES"),
  new GCMParameterSpec(128, iv));
byte[] encrypted = cipher.doFinal(data); // aka cipher text
```

Some notes:
* The initialization vector (IV) is basically salt for encryption.
  Using an unique IV ensures that encrypting the sama data results in a different output each time.
  It is critical that an unique IV is generated each time a key is used.
  Reusing an IV will open different possitilities for attacks, including compromising the key.
  The value of the IV is not a secret and it is needed later to decrypt the data.
* The recommended key size for AES is 256-bit (32 bytes).
  The encryption is as strong as the key.
  Generate a strong key using SecureRandom or use PBKDF2 on a password.
* AES/GCM automatically hashes the encrypted data and secures the hash with the encryption key.
  This is used to detect undesired modifications to the cipher text on decryption.
  The magic value 128 passed to the GCMParameterSpec constructor specifies the hash size (in bits).
  Don't poke it unless you know what you're doing.

Decryption is similar to the encryption in Java:
```
// bytes to be decrypted
byte[] encrypted;

// the key and iv that were used for encryption
byte[] key;
byte[] iv;

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.DECRYPT_MODE,
  new SecretKeySpec(key, "AES"),
  new GCMParameterSpec(128, iv));
byte[] data = cipher.doFinal(encrypted);
```

Note that AES is not the only cipher and GCM is not the only mode.
Other ciphers and modes have different security properties.

## Asymmetric crypto

The encryption we used above used the same key to both encrypt and decrypt the data (symmetric key encryption).
That's a very fast, secure and efficient tool, but it assumes that there is a shared password / encryption key available.

Asymmetric crypto uses a different approach.
The foundation for it is the asymmetric key pair - a pair of a public and a private key.
Only the owner of the key pair should have the private key, but the public key can be shared with anyone.
Data that is encrypted using the public key can only be decrypted with the matching private key and vice versa.

### Data encryption

To send an encrypted message to someone, ask them for their public key and encrypt the data using the public key.
Send the cipher text to the key owner.
Only they can decrypt the data because only they have the private key.

Often hybrid encryption is used: the file is encrypted with symmetric encryption and only the symmetric key is encrypted with the recipient's public key.

### Data signing

To create a digital signature, encrypt the data (or just its hash) with your private key.
Send the cipher text and your public key to the recipient.
They can decrypt the data using your public key, therefore it must have been encrypted by your private key.
Only you have the private key, therefore it must be your document.

### ID-cards

The chip on Estionian ID cards hold [two asymmetric key pairs](https://www.id.ee/index.php?id=30228).
The first (PIN1) is used to for authentication and data decryption.
The second (PIN2) is used for digital signatures.

### TLS

All https internet connections are secured using a protocol called TLS (Transport Layer Security).
The web server has a asymmetric key pair (public key + private key).
The client acquires the server's public key.
The server and client use messages protected by asymmetric encryption and digital signatures to negotiate a symmetric encryption key.
The symmetric key is then used with AES (or equivalent) to encrypt all communication.

TLS is very widely used and can be used to secure any TCP based socket communication.
This is built into Java, so you can easily use it in your own applications.

First generate a key pair for the server.
Java includes a command-line program called *keytool* for that.
```
keytool -genkeypair -keyalg ec -dname cn=localhost -validity 365 -keystore keystore.p12 -storetype pkcs12 -storepass secret
```

Next, extract the public key from the key pair and store it separately:
```
keytool -exportcert -keystore keystore.p12 -storetype pkcs12 -storepass secret -file pubkey.der
keytool -importcert -keystore truststore.p12 -storetype pkcs12 -storepass secret -noprompt -file pubkey.der
```

This should generate two files: *keystore.p12* which contains the key pair and *truststore.p12* which contains only the public key.
Only the server should have the file with the private key.
The file with the public key can be distributed with the client.

The server will load its private key and use it to negotiate a secure connection:
```
File storeFile = new File("keystore.p12");
String storePass = "secret";

KeyStore store = KeyStore.getInstance(storeFile, storePass.toCharArray());
KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
kmf.init(store, storePass.toCharArray());
KeyManager[] keyManagers = kmf.getKeyManagers();

SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(keyManagers, null, null);
try (ServerSocket serverSocket = ctx.getServerSocketFactory().createServerSocket(8443)) {
  // use like a regular server socket
}
```

The client will load the server's public key and use it to negotiate a secure connection:
```
File storeFile = new File("truststore.p12");
String storePass = "secret";

KeyStore store = KeyStore.getInstance(storeFile, storePass.toCharArray());
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init(store);
TrustManager[] trustManagers = tmf.getTrustManagers();

SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustManagers, null);
try (Socket socket = ctx.getSocketFactory().createSocket("localhost", 8443)) {
  // use like a regular socket
}
```

The `SSLContext` voodoo is used to create a special type of `ServerSocket` and `Socket`.
When the connection is first established, the encryption is automatically negotiated before any data is sent.
The application never sees any of this negotiation and can simply enjoy the same security that https connections do.
You can observe the negotiation using tools like [wireshark](https://www.wireshark.org/).

## Tasks

Use the templates in this repository to solve the following tasks.

1. Have a classmate calculate the sha-256 hash of a random number from 1-1000 and give you the hex-encoded hash.
   Write a program that finds the number given its hash (use brute force).
2. Encrypt a file using a 4-letter password as the key (without PBKDF2).
   Use brute force to try all 4-letter passwords until you find the password that decrypts the file.
   How long does the brute force attack take?
3. Copy-paste the previous task and modify it to generate the encryption key using PBKDF2 with iteration count 1.
   How long does the brute force attack take?
   Change the iteration count to 1 000 000 and time it again.
4. Pick a random password and hash it with `PBKDF2WithHmacSHA256`.
   Find the iteration count that takes ~500ms on your machine.
5. Write a program that takes a mode string ("encrypt" or "decrypt"), two filenames (input and output) and a password as command line arguments.
   The program should encrypt or decrypt the input file depending on the specified mode.
   Generate the key from the password using PBKDF2, store the salt, iterations and IV with the encrypted data (in the beginning or end of the file).
