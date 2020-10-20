#!/bin/bash

# Need to install wget in the JupyterHub image.

if [ -z ${BASE_URL+x} ]; then
    URL="http://${HOSTNAME}:8081/hub/health";
else
    URL="http://${HOSTNAME}:8081/${BASE_URL}/hub/health";
fi


if wget -O- --server-response  ${URL}; then
    echo "yeah"
    exit 0
else
    echo "nope"
    exit 1
fi


