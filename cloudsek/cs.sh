#!/bin/bash
KEY="\xd3\x7a\x3b\xc0\xcb\x24\xe4\x7d\xbb\x84\x18\xf6\x55\xff\x85\x88\x85\xfb\x10\xb7\xea\xe4\xa1\xda\xf6\x62\x19\x41\xf7\x5a\xad\x73"
AESMODES="-aes-128-cbc -aes-128-cbc-hmac-sha1 -aes-128-cfb -aes-128-cfb1 -aes-128-cfb8 -aes-128-ctr -aes-128-ecb -aes-128-gcm -aes-128-ofb -aes-128-xts -aes-192-cbc -aes-192-cfb -aes-192-cfb1 -aes-192-cfb8 -aes-192-ctr -aes-192-ecb -aes-192-gcm -aes-192-ofb -aes-256-cbc -aes-256-cbc-hmac-sha1 -aes-256-cfb -aes-256-cfb1 -aes-256-cfb8 -aes-256-ctr -aes-256-ecb -aes-256-gcm -aes-256-ofb -aes-256-xts -aes128 -aes192"
for mode in $AESMODES; do
  openssl enc -d -in data -out /tmp/file_"$mode".dec -k $KEY $mode
done

cat /tmp/*.dec
rm -rf /tmp/*.dec
