import os
import shutil
import subprocess
import tempfile
import re
import platform

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
            return shutil.which("cargo") is not None
        return True # Interpreted languages don't need compilation tools

    def compile(self, source_code, language, target_os, out_file, deps=None):
        """
        Compile the source code into a binary.
        
        Args:
            source_code (str or bytes): Source code to compile.
            language (str): 'c', 'go', or 'rs'.
            target_os (str): 'linux' or 'windows'.
            out_file (str): Path to write the output binary.
            deps (list or dict): Optional list of dependencies (mostly for Rust).
        
        Returns:
            bool: True if compilation succeeded, False otherwise.
        """
        
        suffix = f".{language}"
        mode = "w"
        if isinstance(source_code, bytes):
            mode = "wb"

        # Special handling for Rust (Cargo Project)
        if language in ['rs', 'rust']:
            return self._compile_rust_cargo(source_code, target_os, out_file, deps=deps)

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

    def _compile_rust_cargo(self, source_code, target_os, out_file, deps=None):
        """
        Compiles Rust payload using Cargo.
        """
        print(f"[*] Building Rust Cargo project for {target_os}...")
        tmp_dir = tempfile.mkdtemp()
        try:
            # Generate Dependencies String
            dep_str = ""
            if deps:
                for d in deps:
                    if isinstance(d, str):
                        dep_str += f'{d} = "*"\n'
                    elif isinstance(d, dict):
                        for k, v in d.items():
                             # handle complex deps if v is dict (features etc)
                             if isinstance(v, dict):
                                 # Naive TOML serialization for simple cases
                                 props = ", ".join([f'{pk} = {pv if isinstance(pv, list) else f"{pv}"}' for pk, pv in v.items()])
                                 dep_str += f'{k} = {{ {props} }}\n'
                             else:
                                 dep_str += f'{k} = "{v}"\n'

            # Create Cargo.toml
            cargo_toml = f"""
[package]
name = "payload"
version = "0.1.0"
edition = "2021"

[dependencies]
{dep_str}

[profile.release]
opt-level = "z"
lto = true
strip = true
panic = "abort"
"""
            with open(os.path.join(tmp_dir, "Cargo.toml"), "w") as f:
                f.write(cargo_toml)
            
            # Create src directory
            os.makedirs(os.path.join(tmp_dir, "src"))
            
            # Copy stealth.rs if it exists (for Phase 2 Stealth)
            stealth_path = os.path.join(os.path.dirname(__file__), "stealth.rs")
            if os.path.exists(stealth_path):
                shutil.copy(stealth_path, os.path.join(tmp_dir, "src", "stealth.rs"))
                print("[*] Included stealth.rs in compilation.")

            # Write main.rs
            if isinstance(source_code, bytes):
                source_code = source_code.decode()
                
            with open(os.path.join(tmp_dir, "src", "main.rs"), "w") as f:
                f.write(source_code)
            
            # Build command
            cmd = ["cargo", "build", "--release"]
            
            # Intelligent Cross-Compilation Check
            host_os = platform.system().lower()
            
            target_flag = None
            artifact_subdir = "target/release"

            if target_os == 'windows':
                if host_os == 'linux':
                    # Cross-compiling from Linux to Windows
                    target_flag = "x86_64-pc-windows-gnu"
                    # Check if target is installed
                    try:
                        targets = subprocess.check_output(["rustup", "target", "list", "--installed"], text=True)
                        if target_flag not in targets:
                            print(f"[!] Warning: Rust target {target_flag} not installed. Build may fail.")
                    except:
                        pass # Rustup might not be in path
                    
                    cmd.extend(["--target", target_flag])
                    artifact_subdir = f"target/{target_flag}/release"
                elif host_os == 'windows':
                    # Native build, no target flag needed usually, or use msvc
                    pass

            subprocess.check_call(cmd, cwd=tmp_dir)
            
            # Locate artifact
            bin_name = "payload.exe" if target_os == 'windows' else "payload"
            artifact_path = os.path.join(tmp_dir, artifact_subdir, bin_name)
            
            if os.path.exists(artifact_path):
                shutil.copy(artifact_path, out_file)
                self._check_binary_hygiene(out_file)
                return True
            else:
                print(f"[-] Artifact not found at {artifact_path}")
                return False

        except subprocess.CalledProcessError as e:
            print(f"[-] Cargo build failed: {e}")
            return False
        except Exception as e:
            print(f"[-] Error during Cargo build: {e}")
            return False
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

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

