#!/usr/bin/env bash

if [[ -z "$DO_TOKEN" ]]; then
  echo "This example uses DigitalOcean API key to set DNS entries, DO_TOKEN is required" >&2
  exit 2
fi

if [[ ! -f "../../bin/ssh-verify" ]]; then
  {
    echo "The ssh-verify utility has not been built."
    echo "Use make -c cli from the root directory to build it."
  } >&2
  exit 3
fi

set -euo pipefail

cleanup() {
  echo "Cleaning up"
  while read -r file; do rm -fr "$file" 2>/dev/null; done < .gitignore
}

usage() {
  echo "usage: $0 <domain>" >&2
  exit 1
}

set-dns-txt-record() {
  declare domain="$1" name="$2"

  local payload
  payload="$(
    jq -n \
      --arg type TXT \
      --arg name "$name" \
      --arg data "$(cat "id_ecdsa.pub")" \
      '{ $type, $name, $data }'
  )"

  curl --silent -X POST "https://api.digitalocean.com/v2/domains/$domain/records" \
    --header "Authorization: Bearer $DO_TOKEN" \
    --header "Content-Type: application/json" \
    --data "$payload" >/dev/null
}

main() {
  declare domain="${1:-}"
  if [[ -z "$domain" ]]; then
    usage
  fi
  local namespace="dns-txt-demo"

  trap 'cleanup' EXIT

  # generate a random ecdsa key, because DO has a limit of 512 characters for TXT records
  ssh-keygen -q -t ecdsa -f ./id_ecdsa -N ""

  local host_name
  host_name="dns-txt-demo-"$(openssl rand -base64 8 | tr -dc A-Za-z0-9 | head -c 10)

  set-dns-txt-record "$domain" "$host_name"

  # generate a message
  date > message.txt

  # sign
  ssh-keygen -Y sign -n "$namespace" -f "id_ecdsa" message.txt

  php verify.php "dns://$domain/$host_name" "$namespace" message.txt
}

main "$@"
