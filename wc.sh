#!/bin/sh
if ! command -v find >/dev/null 2>&1; then
    echo "Error: find is required but not installed." >&2
    exit 1
fi
if ! command -v wc >/dev/null 2>&1; then
    echo "Error: wc is required but not installed." >&2
    exit 1
fi
echo "Line count"
find . -path "./.git" -prune -o -type f -exec wc -l {} +
