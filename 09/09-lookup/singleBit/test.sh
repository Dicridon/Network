#!/bin/bash

make clean
make
./router ../forwarding-table.txt
