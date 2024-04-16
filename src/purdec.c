#include <gcrypt.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <unistd.h>
#include <netinet/in.h>

#include "purdec.h"


int main(int argc, char **argv) {
    char password[BUFSIZE];
    char * filename = NULL;
    int port;

    parseArgv(argc, argv, &port, &filename);

    promptPassword(password);


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
