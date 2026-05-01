import re
targets = [
    'hostname:*.dev.life360.com',
    '"hostname:*.dev.life360.com"',
    "'hostname:*.dev.life360.com'"
]

for t in targets:
    m = re.match(r'^\s*[\"\']?hostname\s*:\s*(?P<h>.+)$', t, flags=re.I)
    print(t, '->', m.group('h') if m else None)
