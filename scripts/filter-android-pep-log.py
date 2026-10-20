#!/usr/bin/env python3
"""Read client log lines on stdin; print only fixed PEP warning classifications.

Usage: adb logcat -v brief | python3 scripts/filter-android-pep-log.py
Or: python3 scripts/filter-android-pep-log.py < client.log
Raw input, JIDs, XML, tokens, key material and message text are never printed.
These phrases describe inspected client source, not every client/version.
"""
import json
import sys

PHRASES = {
    "Own device publish attempt threshold exceeded": "empty-device-list-retry-limit",
    "Own device list empty, attempting to publish": "empty-device-list-publish",
    "Error received while publishing own device id": "device-list-publish-error",
    "request for device bundles came back with something other than item-not-found": "bundle-read-error",
    "Error received while publishing bundle": "bundle-publish-error",
}
for line in sys.stdin:
    normalized = " ".join(line.split())
    for phrase, reason in PHRASES.items():
        if phrase in normalized:
            print(json.dumps({"event": "client-pep-warning", "reason": reason}), flush=True)
            break
