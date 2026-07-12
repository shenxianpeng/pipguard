import subprocess
def ls():
    return subprocess.run(['ls', '-la'], capture_output=True)
