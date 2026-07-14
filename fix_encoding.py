#!/usr/bin/env python3
# Fix remaining encoding issues in practica.html
# After the previous ISO-8859-1 fix, Spanish accented chars (in Latin-1 range) are correct
# but chars in CP1252 0x80-0x9F range (em dash, Ó, etc.) are broken.
#
# Known broken byte patterns in current file -> correct UTF-8 bytes:
# EF BF BD 3F 22  (FFFD ? ")  -> E2 80 94  (em dash —)
# EF BF BD 22     (FFFD ")    -> C3 93     (Ó — uppercase O with accent)

import sys

path = r'C:\Users\Daniel\Desktop\valhala\public\practica.html'

with open(path, 'rb') as f:
    data = f.read()

original_len = len(data)
fffd = b'\xef\xbf\xbd'
print(f"File size: {original_len} bytes")
print(f"FFFD occurrences before: {data.count(fffd)}")

# Step 1: Replace em dash pattern (FFFD ? ") -> em dash
em_dash_broken = b'\xef\xbf\xbd\x3f\x22'
em_dash_correct = b'\xe2\x80\x94'
n1 = data.count(em_dash_broken)
data = data.replace(em_dash_broken, em_dash_correct)
print(f"Replaced em dash (FFFD?\"): {n1} occurrences")

# Step 2: Replace Ó pattern (FFFD ") -> Ó
o_broken = b'\xef\xbf\xbd\x22'
o_correct = b'\xc3\x93'
n2 = data.count(o_broken)
data = data.replace(o_broken, o_correct)
print(f"Replaced O-acute (FFFD\"): {n2} occurrences")

# Check remaining FFFD
remaining = data.count(fffd)
print(f"FFFD occurrences after: {remaining}")

if remaining > 0:
    # Show remaining FFFD contexts
    idx = 0
    shown = 0
    while shown < 10:
        pos = data.find(fffd, idx)
        if pos < 0: break
        ctx = data[pos-3:pos+10]
        print(f"  Remaining FFFD at {pos}: {ctx.hex()} | {ctx.decode('utf-8', errors='replace')!r}")
        idx = pos + 3
        shown += 1

with open(path, 'wb') as f:
    f.write(data)

print(f"Written {len(data)} bytes")
print("Done.")
