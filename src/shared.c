// functions used in both purdec and purenc
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "shared.h"

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

/*
 * askForPassword prompts user to a password used for encryption
 */
void promptPassword(char * password) {
    printf("Password to encrypt the files under: ");
    fgets(password, sizeof(password) - 1, stdin);
    return;
}