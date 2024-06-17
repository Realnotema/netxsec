#!/bin/bash

if [[ "$(uname)" == "Linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y make gcc libpcap-dev
    elif command -v yum &> /dev/null; then
        sudo yum install -y make gcc libpcap-devel
    else
        echo "Can't determine OS. QUITTING!"
        exit 1
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    brew install make gcc libpcap 
else
    echo "Unsupported OS. QUITTING!"
    exit 1
fi