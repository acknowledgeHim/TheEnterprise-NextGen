#!/bin/bash

if [ -z "$3" ]; then
    echo "Usage: $0 <path_to_enum4linux.pl> <domain controller ip> <output file>"
        exit 0
    fi

    echo "Running enum4linux\n"
    echo "enum4linux path: $1\n"
    echo "DC IP: $2\n"
    echo "Output file: $3\n"

    $1 $2 >> $3
