from urllib.parse import unquote
with open('payload.txt') as f:
    payloads = f.readlines()

for payload in payloads:
    print(unquote(payload))
