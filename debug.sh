#!/bin/bash -vxxx
exec 2>&1 > $(dirname $0)/output

DIR=$1
PROG=$2
shift 2

echo `pwd` 
echo $PROG $@

$PROG $@  >> $DIR/output 2>&1
