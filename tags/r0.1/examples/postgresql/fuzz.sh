#!/bin/bash

seed=${1:-0}
iter=${2:-4294967295}
prog=${3:-256}
length=${4:-5}

psql test <<EOF
\i fuzzer.sql
select fuzz($seed, $iter, $prog, $length);
EOF
