#!/usr/bin/env python3
# Comprehensive encoding fix for practica.html (pass 2)
# Previous ISO-8859-1 pass fixed Spanish lowercase accented chars.
# This pass fixes uppercase accented chars and Unicode symbols.
#
# Mapping (longer patterns first to avoid prefix conflicts):
#   EF BF BD 73 EF BF BD C2 A0  ->  E2 9A A0 C2 A0   (warning sign ⚠ + NBSP)
#   EF BF BD 73                 ->  C3 9A             (Ú, uppercase U-acute)
#   EF BF BD 6F 2D              ->  E2 9C 97          (ballot X ✗, U+2717)
#   EF BF BD 6F 22              ->  E2 9C 93          (check mark ✓, U+2713)
#   EF BF BD 6F                 ->  C3 9C             (Ü, uppercase U-umlaut)
#   EF BF BD 3F                 ->  C3 89             (É, uppercase E-acute)
#   EF BF BD 27                 ->  C3 91             (Ñ, uppercase N-tilde)
#   EF BF BD 2D                 ->  C3 97             (× multiplication sign, U+00D7)

path = r'C:\Users\Daniel\Desktop\valhala\public\practica.html'

with open(path, 'rb') as f:
    data = f.read()

fffd = b'\xef\xbf\xbd'
print(f"FFFD occurrences before: {data.count(fffd)}")

replacements = [
    # Most specific patterns first
    (b'\xef\xbf\xbd\x73\xef\xbf\xbd\xc2\xa0', b'\xe2\x9a\xa0\xc2\xa0'),  # ⚠ + NBSP
    (b'\xef\xbf\xbd\x73',                      b'\xc3\x9a'),              # Ú
    (b'\xef\xbf\xbd\x6f\x2d',                  b'\xe2\x9c\x97'),          # ✗
    (b'\xef\xbf\xbd\x6f\x22',                  b'\xe2\x9c\x93'),          # ✓
    (b'\xef\xbf\xbd\x6f',                       b'\xc3\x9c'),              # Ü
    (b'\xef\xbf\xbd\x3f',                       b'\xc3\x89'),              # É
    (b'\xef\xbf\xbd\x27',                       b'\xc3\x91'),              # Ñ
    (b'\xef\xbf\xbd\x2d',                       b'\xc3\x97'),              # ×
]

for old, new in replacements:
    n = data.count(old)
    data = data.replace(old, new)
    print(f"  {old.hex()} -> {new.hex()}: {n} replacements")

remaining = data.count(fffd)
print(f"\nFFfD occurrences after: {remaining}")

if remaining > 0:
    idx = 0
    while True:
        pos = data.find(fffd, idx)
        if pos < 0: break
        ctx = data[max(0,pos-20):pos+20]
        print(f"  Remaining at {pos}: {ctx.decode('utf-8', errors='replace')!r}")
        idx = pos + 3

with open(path, 'wb') as f:
    f.write(data)

print(f"\nWritten. File size: {len(data)} bytes")
