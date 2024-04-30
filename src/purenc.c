#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <math.h>

#include "purenc.h"
#include "shared.c"


Config config; // config parsed from command line
int g_encrypt_size; // the size of most recent encrypted message

/*
 * Encrypt buf in-place using AES256
 */
void * encrypt_buf(char * buf, int size, void * key) {
    // cipher handler
    gcry_cipher_hd_t * hd = (gcry_cipher_hd_t  *) malloc(sizeof(gcry_cipher_hd_t ));
    gcry_error_t err = gcry_cipher_open(hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    if (err) {
        fprintf(stderr, "gcry_cipher_open failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    err = gcry_cipher_setkey(*hd, key, 32);
    if (err) {
        fprintf(stderr, "gcry_cipher_setkey failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    err = gcry_cipher_encrypt(*hd, buf, size, NULL, 0);
    if (err) {
        fprintf(stderr, "gcry_cipher_encrypt failed: %s\n", gcry_strerror(err));
        exit(1);
    }
    gcry_cipher_close(*hd);
    
    g_encrypt_size = size;
    return buf;
}

/*
 * Wrapper method for opening and then encrypt the file
 */
void * encyrpt_file(char * input_file_name, void * key) {
    // read the file
    FILE * fp = fopen(input_file_name, "r");
    // get file size
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *file_buf = (char *) malloc(size);
    if (fread(file_buf, 1, size, fp) != size) {
        perror("fread");
        exit(1);
    }
    fclose(fp);

    encrypt_buf(file_buf, size, key);

    return file_buf;
}

/* 
 *  Send a (encrypted) file to the remote
 *  Its also encryted (some data) again using the shared secret derived from diffie-hellman (For no reason since we are manually typing the password to encrypt the file already)
 *  Its also possible to encrypt all the data using this shared secret but I dont think DH is required at all so I didnt bother
 */
void send_file(int sockfd, void * buf, int size, long long shared_secret, char * filename) {
    // artificially increase the share secret length to make it work with aes256 32 byte key len (prepanded zeroes effectly make it less secure. Use of proper secure prng is needed)
    char * key = malloc(32);
    bzero(key, 32);
    *key = shared_secret;

    // send filename
    int len = strlen(filename); 
    write(sockfd, &len, sizeof(int));
    write(sockfd, filename, len);

    // send thr rest
    void * buf_ = malloc(size);
    memcpy(buf_, buf, size);

    write(sockfd, &size, sizeof(int));

    encrypt_buf(buf_, size, key); // the only part that is encrypted by the shared secret from DH.
    write(sockfd, buf_, size);
    
}

/*
 * Entry of the program. 
 */
int main(int argc, char **argv) {
    parseArgv(argc, argv);
    char password[BUFFSIZE];
    promptPassword(password);

    void * salt = gcry_random_bytes (8, GCRY_STRONG_RANDOM);

    void * key = derive_key(password, salt);
    void * cipher = encyrpt_file(config.input_file_name, key);
    int encrypt_size = g_encrypt_size;

    // HMAC || salt || cipher
    void * salt_cipher = malloc(encrypt_size + 8);
    memcpy(salt_cipher, salt, 8);
    memcpy(salt_cipher + 8, cipher, encrypt_size);
    unsigned char * hash = HMAC(salt_cipher, encrypt_size + 8, key);
    void * hmac_salt_cipher = malloc(encrypt_size + 8 + 32);
    memcpy(hmac_salt_cipher, hash, 32);
    memcpy(hmac_salt_cipher + 32, salt_cipher, encrypt_size + 8);

    printf("Successfully encrypted the file %s\n", config.input_file_name);

    // Need to perform remote mode
    if ((config.mode & REMOTE) != 0) {
        // set up tcp connection
        int status, vread, sockfd;
        struct sockaddr_in server_addr;
        char buffer[BUFFSIZE];
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socked failed");
            exit(1);
        }
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(config.port); 
        if (inet_pton(AF_INET, config.ip, &server_addr.sin_addr) < 0) {
            perror("inet pton");
            exit(1);
        }

        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr))) {
            printf("Cannot connect to the server\n");
            exit(0);
        }

        //==============begin diffie-hellman=============
        unsigned int * a = gcry_random_bytes(4, GCRY_STRONG_RANDOM);
        unsigned int x = *a % P;
        unsigned long long e = naive_pow(G, x, P);

        // (1) send e
        write(sockfd, &e, sizeof(unsigned long long));

        gcry_sexp_t pub_key, private_key;
        rsa_key_gen(&pub_key, &private_key);
    
        // recieve (2) k_s
        int len;
        vread = read(sockfd, &len, sizeof(int));
        vread = read(sockfd, buffer, len);
        char * k_s = malloc(vread + 1);
        strncpy(k_s, buffer, vread);


        // receive (3) f
        unsigned long long f;
        vread = read(sockfd, &f, sizeof(unsigned long long));

        // receive (4) signature of H
        len = 0;
        vread = read(sockfd, &len, sizeof(int));
        vread = read(sockfd, buffer, len);
        char * h_signature = malloc(vread + 1);
        strncpy(h_signature, buffer, vread);

        // verify k_s (host key)
        // Not implemented

        // calculate shared secret
        long long k = naive_pow(f, x, P);

        //===========End of DH=================

        send_file(sockfd, hmac_salt_cipher, encrypt_size + 32 + 8, k, config.input_file_name);
        printf("Transmitted to %s:%d\n", config.ip, config.port);
    }

    // perform local mode when needed
    if ((config.mode & LOCAL) != 0) {
        char output_file_name[strlen(config.input_file_name) + 4];
        strncpy(output_file_name, config.input_file_name, strlen(config.input_file_name));
        strcpy(output_file_name + strlen(config.input_file_name), ".pur");
        // check the existance of the output file
        if (access(output_file_name, F_OK) == 0) {
            fprintf(stderr, "%s exists. abort\n", output_file_name);
            exit(1);
        }
        else {
            // save the file
            FILE * fp = fopen(output_file_name, "wb");
            fwrite(hmac_salt_cipher, 32 + 8 + encrypt_size, 1, fp);
            fclose(fp);
        }
        printf("Encrypted file has been saved to %s\n", output_file_name);
    }
    return 0;
}

/* 
 * Display help message on how to call this program
 */
void displayHelp() {
    printf("Usuage: purenc <input file> [-d <output IP-addr:port>] [-l]\n");
}


/*
 * Parse the command line argument to determine the inputfile, mode, and remote address when applicable.
 */
void parseArgv(int argc, char **argv) {
    if (argc < 3) {
        displayHelp();
        exit(0);
    }

    config.input_file_name = argv[1];

    // can be improved with better parsing using loop
    // Written in a way that is assumed local and remote mode would not be used at the same time lead to awkward modification
    if (!strcmp("-d", argv[2])) {
        if (argc == 4 || argc == 5) {
            config.mode = REMOTE;
            char * sep = strchr(argv[3], ':');
            if (sep == NULL) {
                displayHelp();
                exit(0);
            }
            int ip_len = sep - argv[3];

            if (ip_len >= MAX_IP_LEN) {
                printf("IP too long\n");
                displayHelp();
                exit(0);
            }
            strncpy(config.ip, argv[3], sep - argv[3]);

            if (strlen(argv[3]) - ip_len == 1) {
                displayHelp();
                exit(0);
            }
            config.port = atoi(argv[3] + ip_len + 1);
            }

            if (argc == 5) {
                config.mode |= LOCAL;
            }
    }
    else if (!strcmp("-l", argv[2])){
        config.mode = LOCAL;
        if (argc == 5) {
            config.mode |= REMOTE;

            char * sep = strchr(argv[4], ':');
            if (sep == NULL) {
                displayHelp();
                exit(0);
            }
            int ip_len = sep - argv[4];

            if (ip_len >= MAX_IP_LEN) {
                printf("IP too long\n");
                displayHelp();
                exit(0);
            }
            strncpy(config.ip, argv[4], sep - argv[4]);

            if (strlen(argv[4]) - ip_len == 1) {
                displayHelp();
                exit(0);
            }
            config.port = atoi(argv[4] + ip_len + 1);
        }
    }
    else {
        displayHelp();
        exit(0);
    }
} 


