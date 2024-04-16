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

int main(int argc, char **argv) {
    parseArgv(argc, argv);

    char password[BUFFSIZE];
    promptPassword(password);

    if (config.mode == REMOTE) {
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

        status = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

        send(sockfd, "Test\n", 5, 0); 

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
 */
void promptPassword(char * password) {
    printf("Password to encrypt the files under: ");
    fgets(password, sizeof(password) - 1, stdin);
    return;
}
