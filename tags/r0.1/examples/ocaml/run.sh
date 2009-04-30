#!/bin/bash


seed=${1:-$((RANDOM*RANDOM+RANDOM))}
while :; do
#  fi
  ./regfuzz fuzzer.ml $seed
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "./regfuzz fuzzer.ml $seed" >> FINDINGS_OCAML
    echo "[!] Crash on $seed!!"
  fi
  seed=$((RANDOM*RANDOM+RANDOM))

done
