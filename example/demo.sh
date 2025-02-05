#!/usr/bin/env bash

cleanup() {
  echo "Cleaning up"
  while read -r file; do rm -fr "$file" 2>/dev/null; done < .gitignore
  kill "$1"
}

BIND_ADDRESS="127.0.0.1:3005"

echo "Starting PHP server on $BIND_ADDRESS"
php -d html_errors=off -S "$BIND_ADDRESS" index.php >/dev/null 2>&1 &
sleep 1
pid=$!
trap 'cleanup $pid' EXIT

ssh-keygen -q -t ecdsa -f ./id_ecdsa -N ""
cut -f 1-2 -d" " <id_ecdsa.pub | sed 's/^/127.0.0.1 /' > known_hosts

../bin/ssh-sign "demo" id_ecdsa.pub message.txt

echo "Sending"

curl \
  --silent \
  --form "message=@message.txt" --form "signature=@message.txt.sig" \
  --form "namespace=demo" \
  "$BIND_ADDRESS"

sleep 2
