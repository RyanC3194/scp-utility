Name: Ryan Chen
puid: 0031427134
purdue email: chen3194@Purdue.edu


List of submitted files: 
 - header/purdec.h
 - header/purenc.h
 - src/purdec.c
 - src/purenc.c
 - src/shared.c
 - Makefile
 - README.txt


Overview of the work accomplished:
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


Design decisions:

I would say most of my design are pretty standard, seperate each part (parse argv, key-gen, encryption/decryption, network) of the program into its own functions. However, there are few parts that isnt the best. 
To start off, the part that parse the command line argument for 'purenc' is written poorly because I didnt account for having both local and remote mode run at the same time, and modifying it led to the messy parsing.
The major design choose that Im not satisfy is the DH part. Once I realize that this part is not strictly necessory (via piazza post @178 and redundent double encryption), I opted into making that part working instead of keep improving it. (such as using mpi to store large prime, verify server integerty, etc). After all, that part is largely taken care of by manually inputting password on both the server and the client. That being said, if I have more time I would defintely try to use a proper safe and large enough prime and a more effecieny modulo calculation.
Another design choise I made is not hide the purdec "daemon". This is because the user needs to input password into it every time a new file is coming from a client, so there isnt much point hiding it.



PBKDF2:
If this extra input refers to iterations, I set it to 600,000 because I search up the recommended iterations for it. And I would say the people setting those recommendation know a lot better than I do.


Number of Hours / level of efforts:
Parsing: ~30 hour, pretty standard stuff
tcp: ~30 minutes, also pretty stndard
key drive + encryption + decryption + HMAC: ~ 5 hours. Mostly spent on documation and debugging, but not that troublsome as it overlaps with lab2
DH: 10 hours ish. A lot of looking at SSH and gcrypt documentation and experimenting. I would say its the most diffucult part for me.

Overall I think its easlier than the VPN lab but slightly harder than the other two.
However, if DH and all secure connection in SSH needs to be (properly) implemented, than it would definitely be way harder.
