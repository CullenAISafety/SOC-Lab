#!/bin/bash
# Simulate malicious activity (safe lab)
# File changes + unauthorized access simulation

# Create test directory
mkdir -p /tmp/testfiles
touch /tmp/testfiles/file{1..5}.txt

# Simulate file tampering
for f in /tmp/testfiles/*; do
  mv "$f" "$f.encrypted"
done

# Simulate sudo misuse
for i in {1..3}; do
  echo "$(date) sudo: unauthorized command attempt by user normaluser" >> /var/log/auth.log
done
