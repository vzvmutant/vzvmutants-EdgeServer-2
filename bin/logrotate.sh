#!/bin/sh

ARCHIVE="/opt/var/log/archives"

# Get date components
YEAR=$(date +%Y)
MONTH=$(date +%m)
DAY=$(date +%d)

# Build archive path
DEST="$ARCHIVE/$YEAR/$MONTH/$DAY"
mkdir -p "$DEST"

# Append logs instead of overwriting
for f in /opt/var/log/messages /opt/var/log/messages.0; do
    [ -f "$f" ] || continue

    base=$(basename "$f")
    destfile="$DEST/$base"

    # Append contents
    cat "$f" >> "$destfile"

    # Remove original so syslogd can recreate it
    rm -f "$f"
done