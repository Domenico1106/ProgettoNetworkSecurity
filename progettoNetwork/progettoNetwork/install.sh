#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Nessun parametro fornito. Usa '1' o '2'."
    exit 1
fi
if [ $1 -eq 1 ]; then
    OAR_FILE=~/mitm-detection-app/target/onos-mitmdetection-2.0.0-SNAPSHOT.oar
    ./onos/bin/onos-app localhost install $OAR_FILE

elif [ $1 -eq 2 ]; then
    OAR_FILE=~/mitm-detection-app2/target/onos-mitmdetection2-2.0.0-SNAPSHOT.oar
    ./onos/bin/onos-app localhost install $OAR_FILE
else
    echo "Parametro non valido. Usa '1' o '2'."
    exit 1
fi