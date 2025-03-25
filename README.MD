Overview:
 - Parse command line argument for both purdec and purenc.
 - Encrypt file using key derived with PBKDF2 from user input password, and attach HMAC to it.
 - Save and/or send the file to remote.
 - Decrypt the said encrypted file and save it appropriately.
 - Receive the encrypted file from remote or from local file.
 - Detect the existance of the output file and abort when they already exists.
 - Perform a simplify version of DH decribed by openSSH's document on page 21
    - Remove the version and algorithm exchange because there is only one
    - Remove the check for server's identity, so we could be communicating with eve for all we know
    - Use a prime that is not remotely big enough to defend against brute force attack
    - Use a really slower exponent algorithm



Code layout:
  - purenc.c: encrypt the local file and save it / send it to remote
    - First parse the command line argument to detemine the input file, mode, and the remote address. Save them in a global struct 
      "confog" (line 217)
    - prompt user input a password, generate a random salt, and derive a key from them. (line 103)
    - If remote mode is included: 
      - Estabalish a tcp connection with the server and perform DH key exchange (line 144)
      - encrypt the encrypted file using the shared secret and send it (along with its HMAC and salt) to the server (line 73)
    - If local mode is included: 
      - Save the encrypted file (with its HMAC and salt) to the local file system with .pur extension (line 186)
    - For encrypting the file:
      - Generate a random salt. Use it and the password to derive a key for encryption
      - Encrypt the entire original file
      - Prepand the salt to the encrypted file
      - Calculate HMAC for (Salt || encrypted file)
      - prepand HMAC to it => (HMAC(Salt || encrypted file) || salt || encrypted file)

  - purdec.c: decrypt the local/remote file and save it locally
    - First parse the command line argument to run in local or remote mode (line 292)
    - If run in local mode:
      - Ask for a password to decrypt the file, remove the .pur extension and save the decrypted file. (line 239)
    - If run in remote mode:
      - Function as a daemon waiting incoming connection on a given port (line 151)
      - Once a client connects, use DH to set up shared secret with it. (line 168)
      - Wait until wait until the client sends the encrypted file over. (line 217)
      - decrypt and saveit
    - Decrypt (line 64):
      - derive key using password ans salt (byte 32 to 40) (line 66)
      - compute the hash of byte 40 to the end  (line 68)
      - compare the hash to the first 32 bytes (line 70)
      - Drop it if they are not equal
      - Process to decrypt and save the file if they are equal. (line 77)

  - shared.c: functions that will be used for both purenc and purdec
    - derive key function (line 39)
    - Compute HMAC (line 52)
    - prompt for password (line 74)
    - naive pow for DH (line 83)
    - hash_sha256 for DH (line 95)
    - s expression to string (Line 114)
    - rsa key gen (line 128)



