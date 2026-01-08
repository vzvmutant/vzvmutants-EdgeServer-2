#!/bin/sh

BASE="/opt/var/log"
ARCHIVE="$BASE/archives"

# Get date components
YEAR=$(date +%Y)
MONTH=$(date +%m)
DAY=$(date +%d)

# Build archive path
DEST="$ARCHIVE/$YEAR/$MONTH/$DAY"

# Ensure archive directory exists
mkdir -p "$DEST"

# Move only regular files (skip directories)
for f in "$BASE"/*; do
    [ -f "$f" ] || continue
    mv "$f" "$DEST"/
done