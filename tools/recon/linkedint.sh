#!/bin/bash

if [ -z "$9" ]; then
    echo "Usage: $0 <path to PYTHONv2> <search> <username> <password> <email format> <filter by company> <company id> <domain> <output>"
        exit 0
    fi

    echo "Running LinkedInt"
    echo "LinkedInt path: $3"
    echo "Your IP: $6"
    echo "Output file: $1"

    echo "$1 tools/recon/linkedint/LinkedInt.py $2 $3 '$4' $5 $6 $7 $8 $9"

    $1 tools/recon/linkedint/LinkedInt.py -s $2 -u $3 -p '$4' -f $5 -c $6 -i $7 -d $8 -o $9

    #$1 $3 $4 $5 $6 $7 | tee -a $1
    #$2 $3 $4 $5 $6 $7 >> $1
