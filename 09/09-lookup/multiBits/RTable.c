#include "RTable.h"
#include <stdbool.h>
static inline int getIndexFromIP(uint32_t IP){
    return IP >> 30;
}

void initNode(Node *node){
    for (int i = 0; i < NUM_CHILDREN; i++) {
        node->nodeKind[i] = Internal;
        node->children[i] = NULL;
        node->port[i] = -1;
    }
}

void initTree(RTableTree *tree) {
    initNode(tree);
}

Node *createNewNode() {
    Node *returnNode = (Node*)malloc(sizeof(Node));
    if (returnNode != NULL) {
        initNode(returnNode);
        return returnNode;
    } else {
        fprintf(stdout, "No memory\n");
    }
    return NULL;
}

// set bitfileds of a node
void setNode(Node* node, PortID port, NodeKind nodeKind, int index) {
    node->nodeKind[index] = nodeKind;
    node->port[index] = port;
}

// add a new IP to the correct node of a tree
void addNewIP(RTableTree *tree, uint32_t IP, int prefixLength, PortID port) {
    int index = getIndexFromIP(IP);
    if (tree->children[index] == NULL) {
        tree->children[index] = createNewNode();
        if (tree->children[index] == NULL) {
            fprintf(stdout, "No memory\n");
            exit(-1);
        }
    }
    if (prefixLength <= 2) {
        setNode(tree, port, Matched, index);
    } else {
        addNewIP(tree->children[index], IP << 2, prefixLength - 2, port);
    }
}

static bool isLeaf(RTableTree *tree) {
    for (int i = 0; i < NUM_CHILDREN; i++) {
        if (tree->children[i] != NULL) {
            return false;
        }
    }
    return true;
}

static void matchIPHelper(RTableTree *tree, uint32_t IP, PortID *portPtr){
    int index = getIndexFromIP(IP);
    if (tree->nodeKind[index] == Matched)
        *portPtr = tree->port[index];
    
    if (isLeaf(tree)) {
        return;
    } else {
        matchIPHelper(tree->children[index], IP << 2, portPtr);
    }
}

PortID matchIP(RTableTree *tree, uint32_t IP) {
    PortID portID = -1;
    matchIPHelper(tree, IP, &portID);
    return portID;
}

// recycle all space used by the tree
void destroyTree(RTableTree * tree);
