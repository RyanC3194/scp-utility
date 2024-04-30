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
#include "shared.c"

#define V_C_SIZE 0
#define V_S_SIZE 0

// client's identification string
char * V_C() {
    return "";
}

// server's identification string
char * V_S() {
    return "";
}

// I_C and I_S is ignored



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

void process_file(void * hash, void * salt_cipher, int size, char * password, char * output_file_name) {
    
    void * key = derive_key(password, salt_cipher);
    
    unsigned char * new_hash = HMAC(salt_cipher, size, key);

    if (memcmp(hash, new_hash, 32) != 0) {
        fprintf(stderr, "wrong hash\n");
        //return;
    }
    
    decrypy_file(salt_cipher + 8, size - 8, key);

    FILE * fp_output = fopen(output_file_name, "w");
    fwrite(salt_cipher + 8, size - 8, 1, fp_output);
    fclose(fp_output);

}

char * receive_from_client(int connfd, long long shared_secret) {
    int len;
    read(connfd, &len, sizeof(int));
    printf("Total size to receive: %d\n", len);
    return NULL;
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
        if (listen(sockfd, 10) < 0) {
            perror("Listen failed");
            exit(1);
        }

        gcry_sexp_t pub_key, private_key;
        ssh_rsa_key_gen(&pub_key, &private_key);

        while (true) {
            connfd = accept(sockfd, (struct sockaddr*)&client_address, &addr_len);
            if (connfd < 0) {
                perror("Accept failed");
                exit(1);
            }

            unsigned long long e;
            vread = read(connfd, &e, sizeof(unsigned long long));
            printf("received e: %lld, num bytes: %d\n", e, vread);

            e = *read_buffer;

            //diffie-hellman
            unsigned int * a = gcry_random_bytes(1, GCRY_STRONG_RANDOM);
            unsigned int y = *a % P;
            unsigned long long f = naive_pow(G, y) % P;
            printf("%d %lld\n", y, f);

            unsigned long long k = naive_pow(e, y) % P;

            // H = hash(V_C || V_S || K_S || e || f || K)
            int pub_key_size = gcry_sexp_sprint(pub_key, GCRYSEXP_FMT_ADVANCED, NULL, 0);
            void * buf = malloc(V_C_SIZE + V_S_SIZE + pub_key_size + 3 * sizeof(unsigned long long));
            memcpy(buf, V_C(), V_C_SIZE);
            memcpy(buf + V_C_SIZE, V_S(), V_S_SIZE);
            gcry_sexp_sprint(pub_key, GCRYSEXP_FMT_ADVANCED, buf + V_C_SIZE + V_S_SIZE, pub_key_size);
            memcpy(buf + V_C_SIZE + V_S_SIZE + pub_key_size, &e, sizeof(unsigned long long));
            memcpy(buf + V_C_SIZE + V_S_SIZE + pub_key_size + sizeof(unsigned long long), &f, sizeof(unsigned long long));
            memcpy(buf + V_C_SIZE + V_S_SIZE + pub_key_size + 2 * sizeof(unsigned long long), &k, sizeof(unsigned long long));

            void * hash = hash_sha256(buf, V_C_SIZE + V_S_SIZE + pub_key_size + 3 * sizeof(unsigned long long));
            
            // convert hash to mpi for hashing
            gcry_mpi_t hash_mpi;
            gcry_error_t err = gcry_mpi_scan(&hash_mpi, GCRYMPI_FMT_USG, hash, 32, NULL);

            // convert hash to s-expression
            gcry_sexp_t s_hash, hash_signature;
            err = gcry_sexp_build(&s_hash, NULL, "(data (flags raw) (value %m))", hash_mpi);
            err = gcry_pk_sign(&hash_signature, s_hash, private_key);
            char * pub_key_string = sexp_to_string(pub_key);


            // (2) send K_S
            int len = strlen(pub_key_string);
            send(connfd, &len, sizeof(int), 0);
            printf("|%d|\n", len);
            send(connfd, pub_key_string, strlen(pub_key_string), 0);

            // (3) send f
            printf("%lld\n", f);
            send(connfd, &f, sizeof(unsigned long long), 0);

            // (4) send signature of H
            char * signature_string = sexp_to_string(hash_signature);
            len = strlen(signature_string);
            send(connfd, &len, sizeof(int), 0);
            printf("|%d|\n", len);
            send(connfd, signature_string, strlen(signature_string), 0);
            

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
        
        process_file(hash, file_buf_input + 32, size - 32, password, output_file_name);
    }



    return 0;
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
