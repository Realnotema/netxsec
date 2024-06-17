#!/bin/bash

if [[ "$(uname)" == "Linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y libpcap libnet
    elif command -v yum &> /dev/null; then
        sudo yum install -y libpcap libnet
    else
        echo "Can't determine OS. QUITTING!"
        exit 1
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    brew install libpcap libnet 
else
    echo "Unsupported OS. QUITTING!"
    exit 1
fi