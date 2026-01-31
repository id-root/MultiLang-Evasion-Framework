import pytest
import sys
import os
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from modules.obfuscator import Obfuscator

def test_obfuscate_none():
    obf = Obfuscator()
    payload = "echo test"
    res = obf.obfuscate(payload, "bash", "none")
    assert payload in res
    assert "Signature:" in res

def test_obfuscate_bash_low():
    obf = Obfuscator()
    payload = "echo test"
    res = obf.obfuscate(payload, "bash", "low")
    assert "base64 -d" in res
    # Decode back - Adjusted for new format: eval "$(echo ... | base64 -d)"
    # We need to extract the base64 string from inside the eval
    import re
    match = re.search(r'echo\s+([A-Za-z0-9+/=]+)\s+\|', res)
    assert match is not None
    b64_part = match.group(1)
    decoded = base64.b64decode(b64_part).decode()
    assert payload in decoded
    assert "Signature:" in decoded
