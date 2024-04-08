#include <gcrypt.h>

#include "purdec.h"

char * filename;

int main(int argc, char **argv) {
    parseArgv(argc, argv);
    return 0;
}

void displayHelp() {
    printf("Usuage: purdec [-l <input file>]\n");
}

void parseArgv(int argc, char **argv) {
    if (argc == 1) {
        return;
    }
    if (argc == 3) {
        if (strcmp("-l", argv[1])) {
            displayHelp();
            exit(0);
        }

        filename = argv[2];
        return;
    }
    displayHelp();
    exit(0);

} 
