#!/bin/sh

# Change the PROTOCOL environment variable to set the execution pipeline for the given project
# Possible values are
# 1. HTTP
# 2. FTP
# 3. SMTP
# 4. IRC

PROTOCOL=3

# Don't modify the next line
echo "PROTOCOL=${PROTOCOL}" >> "$GITHUB_ENV"