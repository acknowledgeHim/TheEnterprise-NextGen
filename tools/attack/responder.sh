#!/bin/bash

if [ -z "$7" ]; then
    echo "Usage: $0 <output_path> <path to PYTHONv2> <path to Responder.py> <interface name> -i <your ip address> <responder switches>"
        exit 0
    fi

    echo "Running Responder"
    echo "Responder path: $3"
    echo "Your IP: $6"
    echo "Output file: $1"

    echo "$2 $3 $4 $5 $6 $7 >> $1"

    $2 $3 $4 $5 $6 $7 | tee -a $1

    #$2 $3 $4 $5 $6 $7 >> $1
