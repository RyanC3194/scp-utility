#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "purenc.h"


Config config;
int encrypt_size;

// https://www.gnupg.org/documentation/manuals/gcrypt/Key-Derivation.html
void * derive_key(char * password) {
    int pass_len = strlen(password);
    // no real salt for now
    // TODO: generate random salt
    char salt[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    void * key = malloc(32);

    gcry_kdf_derive(password, pass_len, GCRY_KDF_PBKDF2, GCRY_CIPHER_AES256, salt, 8, 10, 32, key);

    return key;
}

//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-cipher-handles.html
void * encyrpt_file(char * input_file_name, void * key) {
    // cipher handler
    gcry_cipher_hd_t * hd = (gcry_cipher_hd_t  *) malloc(sizeof(gcry_cipher_hd_t ));
    gcry_error_t err = gcry_cipher_open(hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    if (err) {
        fprintf(stderr, "gcry_cipher_open failed: %s\n", gcry_strerror(err));
    }

    err = gcry_cipher_setkey(*hd, key, 32);
    if (err) {
        fprintf(stderr, "gcry_cipher_setkey failed: %s\n", gcry_strerror(err));
    }

    err = gcry_cipher_setiv(*hd, key, 16);
    if (err) {
        fprintf(stderr, "gcry_cipher_setiv failed: %s\n", gcry_strerror(err));
    }


    // read the file
    FILE * fp = fopen(input_file_name, "r");
    // get file size
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("%d\n", size);

    char *file_buf = (char *) malloc(size);
    if (fread(file_buf, 1, size, fp) != size) {
        perror("fread");
        exit(1);
    }
    fclose(fp);

    err = gcry_cipher_encrypt(*hd, file_buf, size, NULL, 0);
    if (err) {
        fprintf(stderr, "gcry_cipher_encrypt failed: %s\n", gcry_strerror(err));
    }

    encrypt_size = size;


    return file_buf;
}


//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html
unsigned char * HMAC(void * m, size_t length, void * key) {
    gcry_md_hd_t *hd;
    gcry_error_t err = gcry_md_open (hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if (err) {
        fprintf(stderr, "gcry_md_open failed: %s\n", gcry_strerror(err));
    }
    err = gcry_md_setkey (*hd, key, 32);
    if (err) {
        fprintf(stderr, "gcry_md_setkey failed: %s\n", gcry_strerror(err));
    }

    gcry_md_final (*hd);

    unsigned char * hash = gcry_md_read (*hd, GCRY_MD_SHA256);
    
    return hash;
}

int main(int argc, char **argv) {
    parseArgv(argc, argv);

    char password[BUFFSIZE];
    promptPassword(password);

    void * key = derive_key(password);
    void * cipher = encyrpt_file(config.input_file_name, key);
    unsigned char * hash = HMAC(cipher, encrypt_size, key);



    if ((config.mode & REMOTE) != 0) {
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

        send(sockfd, "Test\n", 5, 0); 

    }

    if ((config.mode & LOCAL) != 0) {
        // test the existance of the file
        char output_file_name[strlen(config.input_file_name) + 4];
        strncpy(output_file_name, config.input_file_name, strlen(config.input_file_name));
        strcpy(output_file_name + strlen(config.input_file_name), ".pur");
        printf("%s\n", output_file_name);
        if (access(output_file_name, F_OK) == 0) {
            fprintf(stderr, "%s exists. abort\n", output_file_name);
            exit(1);
        }
        else {
            FILE * fp = fopen(output_file_name, "w");
            fwrite(hash, 32, 1, fp);
            fwrite(cipher, encrypt_size, 1, fp);
            fclose(fp);
        }

    }


    return 0;
}

void printConfig() {
    printf("==================================\nCONFIG:\n");
    printf("Input file: %s\n", config.input_file_name);
    if (config.mode == LOCAL) {
        printf("Mode: Local\n");
    }
    else {
        printf("Mode: Remote\n");
        printf("IP: %s\n", config.ip);
        printf("PORT: %d\n", config.port);
    }
    printf("==================================\n");
}

void displayHelp() {
    printf("Usuage: purenc <input file> [-d <output IP-addr:port>] [-l]\n");
}

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
        else {
            displayHelp();
            exit(0);
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
    printConfig();
} 

/*
 * askForPassword prompts user to a password used for encryption
 */
void promptPassword(char * password) {
    printf("Password to encrypt the files under: ");
    fgets(passwoTﬂŒ‡ê˘ cN√_‹#ë<