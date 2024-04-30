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

/*
// standard safe prime for diffie hellman using 2048 bits
// https://www.rfc-editor.org/rfc/rfc3526
// generator: 2
const long BIG_PRIME[64] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1, 
    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD, 
    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245, 
    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED, 
    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE45B3D, 
    0xC2007CB8, 0xA163BF05, 0x98DA4836, 0x1C55D39A, 0x69163FA8, 0xFD24CF5F, 
    0x83655D23, 0xDCA3AD96, 0x1C62F356, 0x208552BB, 0x9ED52907, 0x7096966D, 
    0x670C354E, 0x4ABC9804, 0xF1746C08, 0xCA18217C, 0x32905E46, 0x2E36CE3B, 
    0xE39E772C, 0x180E8603, 0x9B2783A2, 0xEC07A28F, 0xB5C55DF0, 0x6F4C52C9, 
    0xDE2BCBF6, 0x95581718, 0x3995497C, 0xEA956AE5, 0x15D22618, 0x98FA0510, 
    0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF};
*/

// using small prime to test first
// didnt end up using a proper large safe prime because I dont think its within the scope of this assignment
const long long P = 1048343; // the largest safe prime in this list: https://prime-numbers.info/list/safe-primes-page-4
const int G = 2; // 2 is a primitive root of 1048343

/*
 * Derive a key from the user input password and a randomly generated salt
 * https://www.gnupg.org/documentation/manuals/gcrypt/Key-Derivation.html
 */
void * derive_key(char * password, char * salt) {
    int pass_len = strlen(password);
    void * key = malloc(32);
    gcry_kdf_derive(password, pass_len, GCRY_KDF_PBKDF2, GCRY_CIPHER_AES256, salt, 8, 600000, 32, key);
    return key;
}


/*
 * Using SHA256 to calculate HMAC on any message.
 * @Return HMAC_key(m)
 * https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html
 */
unsigned char * HMAC(void * m, size_t length, void * key) {
    gcry_md_hd_t *hd = malloc(sizeof(gcry_md_hd_t));
    gcry_error_t err = gcry_md_open (hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
    if (err) {
        fprintf(stderr, "gcry_md_open failed: %s\n", gcry_strerror(err));
        exit(1);
    }
    err = gcry_md_setkey (*hd, key, 32);
    if (err) {
        fprintf(stderr, "gcry_md_setkey failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    gcry_md_write (*hd, m, length);
    gcry_md_final (*hd);

    unsigned char * hash = gcry_md_read (*hd, GCRY_MD_SHA256);
    
    return hash;
}

/*
 * prompts user for a password for encryption/decryption
 */
void promptPassword(char * password) {
    printf("Password to encrypt/decrypt the file: ");
    fgets(password, sizeof(password) - 1, stdin);
    return;
}

/*
 * Slow and naive way to base^exp % p
 */
unsigned long long naive_pow(unsigned long long base, unsigned long exp, int p) {
    unsigned long long result = 1;
    for (long i = 0; i < exp; i++) {
        result *= base;
        result %= p;
    }
    return result;
}

/*
 * returns the Hash of message using sha256
 */
void * hash_sha256(void * message, size_t length) {
    gcry_md_hd_t *hd = malloc(sizeof(gcry_md_hd_t));
    gcry_error_t err = gcry_md_open (hd, GCRY_MD_SHA256, 0);
    if (err) {
        fprintf(stderr, "gcry_md_open failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    gcry_md_write (*hd, message, length);

    gcry_md_final (*hd);

    unsigned char * hash = gcry_md_read (*hd, GCRY_MD_SHA256);
    
    return hash;
}

/*
 * Convert s-expression to string
 */
char * sexp_to_string(gcry_sexp_t a) {
     char *buf;
     size_t size;

     size = gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
     buf = gcry_xmalloc(size);

     gcry_sexp_sprint(a, GCRYSEXP_FMT_ADVANCED, buf, size);
     return buf;
 }

/*
 * Generate a random rsa key pair
 */
void rsa_key_gen(gcry_sexp_t * pub_key, gcry_sexp_t * private_key) {
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;
    gcry_error_t err = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        fprintf(stderr, "gcry_sexp_build failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        fprintf(stderr, "gcry_pk_genkey failed: %s\n", gcry_strerror(err));
        exit(1);
    }

    
    *pub_key = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    *private_key = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

}
