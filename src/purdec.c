#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "purdec.h"

// https://www.gnupg.org/documentation/manuals/gcrypt/Key-Derivation.html
void * derive_key(char * password) {
    int pass_len = strlen(password);
    // no real salt for now
    // TODO: generate random salt
    char salt[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    void * key = malloc(32 * 8);

    gcry_kdf_derive(password, pass_len, GCRY_KDF_PBKDF2, GCRY_CIPHER_AES256, salt, 8, 10, 32, key);

    return key;
}

//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html
unsigned char * HMAC(void * m, size_t length, void * key) {
    gcry_md_hd_t *hd = malloc(sizeof(gcry_md_hd_t));
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


void * decrypy_file(void * message, int length, void * key) {
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

    err = gcry_cipher_decrypt (*hd, message, length, NULL, 0);
    return message;
}

void process_file(void * hash, void * cipher, int size, char * password, char * output_file_name) {
    unsigned char * new_hash = HMAC(cipher, size, derive_key(password));

    if (memcmp(hash, new_hash, 32) != 0) {
        fprintf(stderr, "wrong hash");
        return;
    }
    
    decrypy_file(cipher, size - 32, derive_key(password));

    FILE * fp_output = fopen(output_file_name, "w");
    fwrite(cipher, size - 32, 1, fp_output);
    fclose(fp_output);

}

int main(int argc, char **argv) {
    char password[BUFSIZE];
    char * filename = NULL;
    int port;

    parseArgv(argc, argv, &port, &filename);

    promptPassword(password);

    // only need to receive file from the client when its not in local mode
    if (filename == NULL) {
        int sockfd, connfd;
        unsigned int addr_len;
        struct sockaddr_in server_address, client_address;
        char read_buffer[BUFSIZE];
        int vread;

        // create socket and bind it to the port specified
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            exit(1);
        }
        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = INADDR_ANY;
        server_address.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
            perror("Bind failed");
            exit(1);
        }
        if (listen(sockfd, 1) < 0) {
            perror("Listen failed");
            exit(1);
        }

        while (true) {
            connfd = accept(sockfd, (struct sockaddr*)&client_address, &addr_len);
            if (connfd < 0) {
                perror("Accept fialed");
                exit(1);
            }

            vread = read(connfd, read_buffer, BUFSIZE - 1);
            printf("%d %s\n", vread, read_buffer);

        }
    }
    else {
        FILE * fp;
        char output_file_name[strlen(filename)];
        strncpy(output_file_name, filename, strlen(filename));
        output_file_name[strlen(filename) - 4] = '\0';
        if (access(output_file_name, F_OK) == 0) {
            fprintf(stderr, "%s exists. abort\n", output_file_name);
            exit(1);
        }
        if (access(filename, F_OK) != 0) {
            fprintf(stderr, "input file does not exist. abort\n", output_file_name);
            exit(1);
        }
        FILE * fp_input = fopen(filename, "r");
        // get file size
        fseek(fp_input, 0, SEEK_END);
        int size = ftell(fp_input);
        fseek(fp_input, 0, SEEK_SET);
        printf("%d\n", size);
        char *file_buf_input = (char *) malloc(size);
        if (fread(file_buf_input, 1, size, fp_input) != size) {
            perror("fread");
            exit(1);
        }
        fclose(fp_input);

        void *hash = malloc(32);
        memcpy(hash, file_buf_input, 32);
        
        void * cipher = malloc(size);
        memcpy(cipher, file_buf_input + 32, size - 32);

        process_file(hash, cipher, size - 32, password, output_file_name);
    }



    return 0;
}

void promptPassword(char * password) {
    printf("Password to decrypt the files under: ");
    fgets(password, sizeof(password) - 1, stdin);
    return;
}

/*
 * displayHelp: Show the correct usuage of the program
 */
void displayHelp() {
    printf("Usuage: purdec [<port>] [-l <input file>]\n");
}

/*
 * praseArgv
 *     Parse command line arguements
 *     Update Global variables 'port' and 'filename'
 * argc: number of command line argument
 * argv: command line arguments
 */
void parseArgv(int argc, char **argv, int * port, char ** filename) {
    if (argc == 2) {
        *port = atoi(argv[1]);
        return;
    }
    if (argc == 3) {
        if (strcmp("-l", argv[1])) {
            displayHelp();
            exit(0);
        }
        *port = -1;
        *filename = argv[2];
        return;
    }
    displayHelp();
    exit(0);

} 
