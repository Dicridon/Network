#include "RTable.h"
#include <stdbool.h>
static inline int getIndexFromIP(uint32_t IP){
    return IP >> 31;
}

void initNode(Node *node){
    node->nodeKind = Internal;
    node->port = -1;
    node->children[LEFT] = NULL;
    node->children[RIGHT] = NULL;
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
void setNode(Node* node, PortID port, NodeKind nodeKind) {
    node->nodeKind = nodeKind;
    node->port = port;
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
    if (prefixLength == 1) {
        setNode(tree->children[index], port, Matched);
    } else {
        addNewIP(tree->children[index], IP << 1, prefixLength - 1, port);
    }
}

static bool isLeaf(RTableTree *tree) {
    return tree->children[LEFT] == NULL && tree->children[RIGHT] == NULL;
}

static void matchIPHelper(RTableTree *tree, uint32_t IP, PortID *portPtr){
    if (!tree)
        return;
    if (tree->nodeKind == Matched)
        *portPtr = tree->port;
    
    if (isLeaf(tree)) {
        return;
    } else {
        matchIPHelper(tree->children[getIndexFromIP(IP)], IP << 1, portPtr);
    }
}

PortID matchIP(RTableTree *tree, uint32_t IP) {
    PortID portID = -1;
    matchIPHelper(tree, IP, &portID);
    return portID;
}

// recycle all space used by the tree
void destroyTree(RTableTree * tree) {
    if (tree->children[LEFT] != NULL)
        destroyTree(tree->children[LEFT]);

    if (tree->children[RIGHT] != NULL)
        destroyTree(tree->children[RIGHT]);

    free(tree);
    tree = NULL;
}
