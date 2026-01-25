import os
import shutil
import subprocess
import tempfile
import re

class Builder:
    """
    Handles compilation of payloads.
    """

    def check_dependencies(self, language, target_os='linux'):
        """
        Check if the necessary compiler is installed for the given language.
        
        Args:
            language (str): 'c', 'go', or 'rs' (rust).
            target_os (str): 'linux' or 'windows'.
        
        Returns:
            bool: True if dependencies are met, False otherwise.
        """
        if language == 'c':
            if target_os == 'windows' and os.name != 'nt':
                 return shutil.which("x86_64-w64-mingw32-gcc") is not None
            return shutil.which("gcc") is not None
        elif language == 'go':
            return shutil.which("go") is not None
        elif language in ['rs', 'rust']:
            return shutil.which("rustc") is not None
        return True # Interpreted languages don't need compilation tools

    def compile(self, source_code, language, target_os, out_file):
        """
        Compile the source code into a binary.
        
        Args:
            source_code (str or bytes): Source code to compile.
            language (str): 'c', 'go', or 'rs'.
            target_os (str): 'linux' or 'windows'.
            out_file (str): Path to write the output binary.
        
        Returns:
            bool: True if compilation succeeded, False otherwise.
        """
        
        suffix = f".{language}"
        mode = "w"
        if isinstance(source_code, bytes):
            mode = "wb"

        # Create temp source file
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, mode=mode, delete=False) as tmp_src:
                tmp_src.write(source_code)
                tmp_src_path = tmp_src.name
            
            print(f"[*] Compiling {language} payload for {target_os}...")

            if language == 'c':
                # GCC compilation
                # Flags: -s (strip), -Os (optimize size), -fno-ident (no ident)
                flags = ["-s", "-Os", "-fno-ident"]
                
                if target_os == 'windows' and os.name != 'nt':
                     cmd = ["x86_64-w64-mingw32-gcc", tmp_src_path, "-o", out_file, "-lws2_32"] + flags
                else:
                    cmd = ["gcc", tmp_src_path, "-o", out_file] + flags
                
                subprocess.check_call(cmd)

            elif language == 'go':
                # Go compilation
                # Flags: -ldflags "-s -w" (strip symbols and debug)
                env = os.environ.copy()
                if target_os == 'windows':
                    env['GOOS'] = 'windows'
                elif target_os == 'linux':
                    env['GOOS'] = 'linux'
                
                # Check for garble
                go_bin = "go"
                if shutil.which("garble"):
                    go_bin = "garble"
                    print("[*] Using garble for Go obfuscation")
                
                cmd = [go_bin, "build", "-ldflags", "-s -w", "-o", out_file, tmp_src_path]
                subprocess.check_call(cmd, env=env)
            
            elif language in ['rs', 'rust']:
                # Rust compilation (using rustc)
                # Flags: -C opt-level=z (size), -C strip=symbols, -C lto=yes
                cmd = ["rustc", tmp_src_path, "-o", out_file, "-C", "opt-level=z", "-C", "strip=symbols", "-C", "lto=yes"]
                if target_os == 'windows':
                     cmd.extend(["--target", "x86_64-pc-windows-gnu"]) # Assumes target is installed/avail
                
                subprocess.check_call(cmd)
            
            # Post-compilation check: Binary Hygiene
            self._check_binary_hygiene(out_file)
            
            return True

        except subprocess.CalledProcessError as e:
            print(f"[-] Compilation failed: {e}")
            return False
        except Exception as e:
            print(f"[-] Error during compilation: {e}")
            return False
        finally:
            if 'tmp_src_path' in locals() and os.path.exists(tmp_src_path):
                os.remove(tmp_src_path)

    def _check_binary_hygiene(self, filepath):
        """
        Scan binary for absolute paths or sensitive strings.
        """
        try:
            with open(filepath, "rb") as f:
                content = f.read()
                
            # Regex for common absolute paths (linux /home/..., windows C:\Users...)
            # We look for strings that are 0-terminated or look like paths
            
            # Simple check for /home/ or C:\Users
            if b"/home/" in content or b"C:\\Users" in content:
                print("[!] WARNING: Absolute paths detected in binary! This affects OpSec.")
                
            # We could also check for "GCC: (GNU)" etc if -fno-ident failed
        except Exception as e:
            print(f"[-] Hygiene check failed: {e}")

