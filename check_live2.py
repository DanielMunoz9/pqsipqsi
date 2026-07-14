#!/usr/bin/env python3
import urllib.request

resp = urllib.request.urlopen('https://bellatorrpg-wpb6ciolhq-uc.a.run.app/practica', timeout=10)
html = resp.read()

# Find ortografia
needle = 'ortograf'.encode()
idx = html.find(needle)
while idx >= 0:
    ctx = html[max(0,idx-5):idx+60]
    print(repr(ctx))
    idx = html.find(needle, idx+1)
