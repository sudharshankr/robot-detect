#!/usr/bin/env bash
echo client start
echo 10.0.1.30 website.com >> /etc/hosts # location of mitm

python3 attack.py -host 10.0.1.30 &

sleep 5
curl -s --insecure --http0.9 https://website.com:4000 --ciphers AES256-SHA:AES256-SHA256

wait
