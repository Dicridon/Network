#!/bin/bash

# for i in `seq 1 4`;
# do
# 	echo "NODE b$i dumps:";
# 	tail -5 b$i-output.txt;
# 	echo "";
# done

pkill -SIGTERM stp

files=$(ls *.txt)
count=0
flag=0
for i in $files;
do
    count=`expr $count + 1`
done

if [[ $count == 6 ]]; then
    echo "Find ${count} files"
    flag=15
else
    echo "Find ${count} files"
    flag=5
fi


for i in $files;
do
    echo "NODE ${i:0:2} dumps"
    tail -$flag $i
    echo"";
done

