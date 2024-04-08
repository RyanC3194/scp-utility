#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

#include "purenc.h"


Config config;

int main(int argc, char **argv) {
    parseArgv(argc, argv);

    char * password = askForPassword();


    free(password);
    exit(0);
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

    if (!strcmp("-d", argv[2])) {
        if (argc != 4) {
            displayHelp();
            exit(0);
        }
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
        
        printf("%s\n", sep);
        
    }
    else if (!strcmp("-l", argv[2])){
        config.mode = LOCAL;
    }
    else {
        displayHelp();
        exit(0);
    }
    printConfig();
} 

/*
 * askForPassword prompts user to a password used for encryption
 * @return: a char pointer to a start of the password string
 */
char * askForPassword() {
    char * pass = (char *) malloc(sizeof(char) * BUFFSIZE);

    printf("Password: ");
    fgets(pass, BUFFSIZE, stdin);

    return pass;
}
