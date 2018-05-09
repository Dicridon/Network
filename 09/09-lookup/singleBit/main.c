#include "dataRead/dataRead.h"
#include "RTable.h"
int main(int argc, char *argv[]) {
    uint32_t IP;
    PortID port;
    int prefixLength;
    if (argc != 2) {
        printf("Usage: ./router filename\n");
		return 0;
    }

    openRTableFile(argv[1]);
    RTableTree *tree = (RTableTree *)malloc(sizeof(RTableTree)); 
    initTree(tree);
    int matchPort;
    for (int i = 0; i < 697882; i++) {
        if (getLine(&IP, &prefixLength, &port) == -1)
            return 0;
        addNewIP(tree, IP, prefixLength, port);
    }
    rewindRTableFile();
    for (int i = 0; i < 697882; i++) {
        if (getLine(&IP, &prefixLength, &port) == -1)
            return 0;
        if ((matchPort = matchIP(tree, IP)) == port) {
            printf("Correct, want %d, given %d\n", port, matchPort);
        } else {
            printf("WRONG!!!!!!!!!!, want %d, given %d\n", port, matchPort);
        }
    }
    destroyTree(tree);
    closeRTableFile();
}
