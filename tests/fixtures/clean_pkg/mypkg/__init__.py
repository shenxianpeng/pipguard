"""Runtime module with network usage — MEDIUM scope (not install hook)."""
import socket


def fetch_data(host, port):
    """Connects to a remote host. MEDIUM risk in runtime, not install hook."""
    s = socket.create_connection((host, port))
    return s.recv(4096)
