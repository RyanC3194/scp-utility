#include <gcrypt.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "purdec.h"


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
