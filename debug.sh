#!/bin/bash

DIR=$1
PROG=$2
shift 2

echo `pwd` > $DIR/pwd
echo $PROG $@ > $DIR/full_cmd

$PROG $@  > $DIR/output 2>&1
