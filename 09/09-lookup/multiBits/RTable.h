#ifndef __RTABLE__
#define __RTABLE__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define NUM_CHILDREN (4)
#define LEFT  (0)
#define RIGHT (1)

typedef enum NodeKind{Internal, Matched} NodeKind;
typedef enum NodeIdentity{Root, Leaf} NodeIdentity;

typedef struct node{
    NodeKind nodeKind[NUM_CHILDREN];
    int port[NUM_CHILDREN];
    struct node *children[NUM_CHILDREN];
} Node;

typedef Node RTableTree;
typedef int PortID ;

void initNode(Node *node);

void initTree(RTableTree* node);

// return an initialized new node
Node *createNewNode();

// set bitfileds of a node
void setNode(Node* node, PortID port, NodeKind nodeKind, int index);

// add a new IP to the correct node of a tree
void addNewIP(RTableTree *tree, uint32_t IP, int prefixLength, PortID port);

PortID matchIP(RTableTree *tree, uint32_t IP);

// recycle all space used by the tree
void destroyTree(RTableTree * tree);
#endif
