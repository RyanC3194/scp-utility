
#ifndef PURENC_H_
#define PURENC_H_

#define BUFFSIZE 1024

char * askForPassword();
void parseArgv(int argc, char **argv);
void printConfig();
char * keyDerive(char * password);

#define MAX_IP_LEN 40

enum Mode {
    LOCAL,
    REMOTE
};

typedef struct {
    enum Mode mode;
    const char *input_file_name;
    char ip[MAX_IP_LEN];
    int port;
} Config;


#endif