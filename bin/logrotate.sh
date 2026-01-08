#!/bin/sh

ARCHIVE="/opt/var/log/archives"

# Get date components
YEAR=$(date +%Y)
MONTH=$(date +%m)
DAY=$(date +%d)

# Build archive path
DEST="$ARCHIVE/$YEAR/$MONTH/$DAY"

# Ensure archive directory exists
mkdir -p "$DEST"

# Move /var/log/messages and /var/log/messages.0 if they exist
for f in /var/log/messages /var/log/messages.0; do
    [ -f "$f" ] || continue
    mv "$f" "$DEST"/
done
