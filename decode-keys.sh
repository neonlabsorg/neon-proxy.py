#!/bin/bash
for k in ./test-operator-keypairs/*.json; do echo $k; solana address -k $k; done
