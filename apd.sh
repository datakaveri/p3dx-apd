#!/bin/bash

echo Starting the APD...

source bin/activate

python3 manage.py qcluster &
sleep 3

python3 manage.py runserver 0.0.0.0:8000

