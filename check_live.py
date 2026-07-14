#!/usr/bin/env python3
import urllib.request

resp = urllib.request.urlopen('https://bellatorrpg-wpb6ciolhq-uc.a.run.app/practica', timeout=10)
html = resp.read().decode('utf-8', errors='replace')

# Find icon strings
for needle in ["lvl===", "makeItem", "textContent = '"]:
    idx = html.find(needle)
    if idx >= 0:
        print(f"Found {needle!r} at {idx}:")
        print(repr(html[idx:idx+200]))
        print()
