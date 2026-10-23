#!/bin/sh
# Fetch the two wordlists the cracker prefers: rockyou.txt and the SecLists
# top-1M list. They are large; existing files are left alone.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WL="$DIR/wordlists"
SEC="$WL/SecLists/Passwords/Common-Credentials"
mkdir -p "$SEC"

if [ ! -s "$WL/rockyou.txt" ]; then
    echo "downloading rockyou.txt (about 134 MB)..."
    curl -L --fail --retry 2 -o "$WL/rockyou.txt.part" \
        'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt'
    mv "$WL/rockyou.txt.part" "$WL/rockyou.txt"
else
    echo "rockyou.txt already present"
fi

if [ ! -s "$SEC/xato-net-10-million-passwords-1000000.txt" ]; then
    echo "downloading SecLists top-1M..."
    curl -L --fail --retry 2 -o "$SEC/xato-net-10-million-passwords-1000000.txt.part" \
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt'
    mv "$SEC/xato-net-10-million-passwords-1000000.txt.part" \
       "$SEC/xato-net-10-million-passwords-1000000.txt"
else
    echo "SecLists top-1M already present"
fi

echo
echo "wordlists:"
echo "  $WL/rockyou.txt ($(wc -l < "$WL/rockyou.txt") lines)"
echo "  $SEC/xato-net-10-million-passwords-1000000.txt ($(wc -l < "$SEC/xato-net-10-million-passwords-1000000.txt") lines)"
echo
echo "The cracker prefers rockyou, then SecLists, then common.txt."
