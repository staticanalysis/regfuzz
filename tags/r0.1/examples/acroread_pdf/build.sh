#!/bin/bash
cat test-header.pdf ${1:-test.js} test-footer.pdf > test.pdf
