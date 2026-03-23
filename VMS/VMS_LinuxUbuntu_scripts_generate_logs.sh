#!/bin/bash
# Generate normal and suspicious Linux logs
# Run as root

# Normal login events
for i in {1..5}
do
  echo "$(date) user login: normaluser" >> /var/log/auth.log
done

# Normal process creation
for i in {1..3}
do
  echo "$(date) Process started: nginx" >> /var/log/syslog
done

# Simulate suspicious activity: failed login attempts
for i in {1..5}
do
  echo "$(date) Failed password for root from 192.168.56.20" >> /var/log/auth.log
done
