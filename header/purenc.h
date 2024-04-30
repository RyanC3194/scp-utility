
#ifndef PURENC_H_
#define PURENC_H_

#define BUFFSIZE 1024

void promptPassword(char *);
void parseArgv(int argc, char **argv);
void printConfig();
void * encyrpy_file(char * password, void *key);

#define MAX_IP_LEN 40
#define BUFSIZE 1024

enum Mode {
    LOCAL = 1,
    REMOTE = 2
};

typedef struct {
    enum Mode mode;
    char *input_file_name;
    char ip[MAX_IP_LEN];
    int port;
} Config;


#endif