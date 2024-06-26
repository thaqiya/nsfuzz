#!/bin/bash

set -x

CLANG=${CLANG:-clang}
$CLANG $@

PATTERN1='-o [^ ]*\.o'
PATTERN2='-o .*'
if [[ $@ =~ $PATTERN1 ]]; then
        PREFIX=`echo $@ | sed -e 's/\(.*-o\) .*/\1/'`
        FILE_NAME=`echo $@ | sed -e 's/.*-o \(.*\)/\1/'`
        BC_NAME=`echo $FILE_NAME | sed -e 's/\.o/\.llbc/'`
elif [[ ! $@ =~ $PATTERN2 ]]; then
        PREFIX="$@ -o"
        FILE_NAME=`echo $@ | sed -e 's/.*-c.*\( .*.c\)/\1/'`
        BC_NAME=`echo $FILE_NAME | sed -e 's/\.c/\.llbc/'`
fi

if [ ! -z "$PREFIX" ]; then
        $CLANG -emit-llvm -g $PREFIX $BC_NAME -O0
fi