#!/bin/bash

seed=${1:-0}
iter=${2:-4294967295}
prog=${3:-128}
length=${4:-5}

psql test <<EOF
\i cfuzzer.sql
select cfuzz($seed, $iter, $prog, $length);
EOF
