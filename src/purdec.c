#include <gcrypt.h>

#include "purdec.h"

char * filename;
int port;

int main(int argc, char **argv) {
    parseArgv(argc, argv);
    return 0;
}

void displayHelp() {
    printf("Usuage: purdec <port> [-l <input file>]\n");
}

void parseArgv(int argc, char **argv) {
    if (argc == 2) {
        port = atoi(argv[1]);
        return;
    }
    if (argc == 4) {
        if (strcmp("-l", argv[2])) {
            displayHelp();
            exit(0);
        }

        filename = argv[3];
        return;
    }
    displayHelp();
    exit(0);

} 
