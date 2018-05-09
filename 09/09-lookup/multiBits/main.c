#include "dataRead/dataRead.h"
#include "RTable.h"

#define LINES (697882)

int main(int argc, char *argv[]) {
    uint32_t IP;
    PortID port;
    int prefixLength;
    if (argc != 2) {
        printf("Usage: ./router filename\n");
		return 0;
    }

    openRTableFile(argv[1]);
    RTableTree tree;
    initTree(&tree);
    int matchPort;
    for (int i = 0; i < LINES; i++) {
        getLine(&IP, &prefixLength, &port);
        addNewIP(&tree, IP, prefixLength, port);
    }

    rewindRTableFile();
    
    for (int i = 0; i < LINES; i++) {
        if ((matchPort = matchIP(&tree, IP)) == port) {
            printf("Correct, want %d, given %d\n", port, matchPort);
        } else {
            printf("WRONG!!!!!!!!!!, want %d, given %d\n", port, matchPort);
        }
    }
    
    closeRTableFile();
}
