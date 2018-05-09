#ifndef __DATA_READ__
#define __DATA_READ__

// #define __DEBUG__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../RTable.h"

FILE *RTableFile;

void openRTableFile(const char * file) {
    RTableFile = fopen(file, "rb");
    if (RTableFile == NULL) {
        printf("Can not open file %s\n", file);
    }
}

int getLine(uint32_t *IP, int *prefixLength, PortID *port) {
    uint32_t IP3 = 0;
    uint32_t IP2 = 0;
    uint32_t IP1 = 0;
    uint32_t IP0 = 0;
    if (fscanf(RTableFile,
               "%u.%u.%u.%u %d %d",
               &IP3, &IP2, &IP1, &IP0,  prefixLength, port) == EOF) {
        printf("EOF, No line available\n");
        return -1;
    }
#ifdef __DEBUG__
    printf("%u.%u.%u.%u %d %d\n", IP3, IP2, IP1, IP0, *port, *prefixLength);
#endif
    *IP = ((IP3 & 0x000000ff) << 24) |
          ((IP2 & 0x000000ff) << 16) |
          ((IP1 & 0x000000ff) << 8) |
          ((IP0 & 0x000000ff));
    return 0;
}

void rewindRTableFile() {
    fseek(RTableFile, 0, SEEK_SET);
}

void closeRTableFile() {
    fclose(RTableFile);
}
#endif
