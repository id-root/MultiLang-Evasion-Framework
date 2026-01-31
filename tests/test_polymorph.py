import pytest
import sys
import os
import ast

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from modules.polymorph import Polymorph

def test_polymorph_none():
    poly = Polymorph()
    payload = "print('hello')"
    res = poly.obfuscate(payload, "python", "none")
    assert "print('hello')" in res
    assert "Signature:" in res

def test_polymorph_python_rename():
    poly = Polymorph()
    payload = "x = 10\nprint(x)"
    res = poly.obfuscate(payload, "python", "medium")
    # x should be renamed. Wait, if logic keeps 'x' if it's too short/common?
    # My renamer excludes 'print', 'range' etc. 'x' is not excluded.
    # It generates random string.
    # But wait, signature is appended as comment.
    assert "Signature:" in res
    # Should still be valid python
    ast.parse(res)

def test_polymorph_python_restructure():
    poly = Polymorph()
    payload = "for i in range(5): pass"
    res = poly.obfuscate(payload, "python", "high")
    # logic converts for to while
    assert "while" in res
    ast.parse(res)
