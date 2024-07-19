#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Nessun parametro fornito. Usa '1' o '2'."
    exit 1
fi
if [ $1 -eq 1 ]; then
    (cd ~/mitm-detection-app && make compile)

elif [ $1 -eq 2 ]; then
    (cd ~/mitm-detection-app2 && make compile)
else
    echo "Parametro non valido. Usa '1' o '2'."
    exit 1
fi

