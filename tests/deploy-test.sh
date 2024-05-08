#!/bin/bash
# set -xeuo pipefail
set -e

START_DIR=$1
TEST_NAME=$2

echo "Deploy test ..."
source .venv/bin/activate && python3 -m unittest discover -s $START_DIR -v -p $TEST_NAME
echo "Deploy test success"

exit 0
