#!/bin/sh
# من مجلد deploy:  sh tools/release.sh <نسخة النظام inventory-system.html>
set -e
cd "$(dirname "$0")/.."
SRC="${1:-inventory-system.html}"
python3 tools/build.py "$SRC"
[ "$SRC" = inventory-system.html ] || cp "$SRC" inventory-system.html
date -u +"build %Y-%m-%d %H:%M UTC" > VERSION
rm -f ../inventory-server.zip ../inventory-update.zip
zip -rq ../inventory-server.zip . -x "data/*" "*.zip" ".git/*" "inventory-system.html"
zip -rq ../inventory-update.zip public permissions.json server.js VERSION
ls -la ../inventory-*.zip
