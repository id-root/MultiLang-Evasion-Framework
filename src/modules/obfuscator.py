import base64
import random
import string
import re

class Obfuscator:
    """
    Handles obfuscation of payloads for different languages.
    """

    def obfuscate(self, payload, language, level="none"):
        """
        Obfuscate the payload based on language and level.
        """
        # Always add a unique signature
        payload = self._add_unique_signature(payload, language)

        if level == "none":
            return payload
        
        if language == "bash":
            return self._obfuscate_bash(payload, level)
        elif language == "ps1":
            return self._obfuscate_ps1(payload, level)
        elif language == "js":
            return self._obfuscate_js(payload, level)
        elif language == "c":
            return self._obfuscate_c(payload, level)
        else:
            return payload

    def _add_unique_signature(self, payload, language):
        sig = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        if language in ['c', 'js', 'go', 'rs']:
            return payload + f"\n// Signature: {sig}"
        elif language in ['bash', 'ps1', 'py']:
            return payload + f"\n# Signature: {sig}"
        return payload

    def _obfuscate_bash(self, payload, level):
        layers = 1
        if level == "medium":
            layers = 2
        elif level == "high":
            layers = 3
        
        current = payload
        for _ in range(layers):
            encoded = base64.b64encode(current.encode()).decode()
            current = f"eval \"$(echo {encoded} | base64 -d)\""
        return current

    def _obfuscate_ps1(self, payload, level):
        # 1. Variable Renaming (Logic-Based)
        if level in ["medium", "high"]:
            vars_found = set(re.findall(r'\$[a-zA-Z0-9_]+', payload))
            exclude = {'$true', '$false', '$null', '$args', '$ErrorActionPreference', '$env'}
            mapping = {}
            for v in vars_found:
                if v.lower() not in [x.lower() for x in exclude]:
                    new_name = "$" + ''.join(random.choices(string.ascii_letters, k=random.randint(4, 8)))
                    mapping[v] = new_name
            
            for v in sorted(mapping.keys(), key=len, reverse=True):
                payload = payload.replace(v, mapping[v])

        # 2. Random Case (Logic-Based)
        if level == "high":
            new_payload = []
            for char in payload:
                if char.isalpha() and random.random() > 0.5:
                    new_payload.append(char.swapcase())
                else:
                    new_payload.append(char)
            payload = "".join(new_payload)

        # 3. Base64 Encoding wrapper
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        return cmd

    def _obfuscate_js(self, payload, level):
        hex_payload = "".join([f"\\x{ord(c):02x}" for c in payload])
        obf = f"eval('{hex_payload}')"
        if level in ["medium", "high"]:
            obf = f"(function(){{ {obf} }})()"
        return obf

    def _obfuscate_c(self, payload, level):
        """
        Obfuscate C payload using Heavy Opaque Predicates (Junk Code).
        Removed structural CFF to avoid scope/compilation issues.
        """
        lines = payload.split('\n')
        obfuscated = []
        
        for line in lines:
            stripped = line.strip()
            
            # Preserve preprocessor directives and comments
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                obfuscated.append(line)
                continue
            
            # Append the original line first
            obfuscated.append(line)

            # Insert Heavy Opaque Predicates AFTER valid statements
            # Ensure we are inside a function (heuristic: indentation > 0) or simply check for end of statement
            # Skip control flow keywords to avoid breaking logic structure (e.g. if (..) stmt; -> if (..) stmt; junk;)
            # But inserting after 'return' or 'break' is useless/unreachable code (dead code), which is fine but clang might warn.
            
            is_statement = stripped.endswith(";")
            is_keyword = any(stripped.startswith(kw) for kw in ["return", "break", "continue", "goto", "typedef"])
            
            if level in ["medium", "high"] and is_statement and not is_keyword:
                # 30% chance to insert a junk block
                if random.random() > 0.7:
                    # Generate random numbers for predicate
                    r1 = random.randint(10, 99)
                    r2 = random.randint(10, 99)
                    res = (r1 * r2) % 2
                    
                    # Target value that makes it false
                    target = 1337
                    if res == target: target += 1 # Ensure it's false
                    
                    # Junk block
                    junk_var_name = "_" + ''.join(random.choices(string.ascii_letters, k=4))
                    predicate = f"if (({r1} * {r2}) % 2 == {target})"
                    junk_body = f"{{ int {junk_var_name} = 0; {junk_var_name}++; }}"
                    
                    # Indent to match previous line
                    indent = len(line) - len(line.lstrip())
                    indent_str = " " * indent
                    
                    obfuscated.append(f"{indent_str}{predicate} {junk_body}")
            
            # Random comments
            if random.random() > 0.9:
                indent = len(line) - len(line.lstrip())
                indent_str = " " * indent
                rnd = ''.join(random.choices(string.ascii_letters, k=6))
                obfuscated.append(f"{indent_str}/* {rnd} */")

        return "\n".join(obfuscated)
