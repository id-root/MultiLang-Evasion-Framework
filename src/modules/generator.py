import os
from jinja2 import Environment, FileSystemLoader

class Generator:
    """
    Handles the generation of payloads using Jinja2 templates.
    """

    def __init__(self):
        """
        Initialize the Generator with the templates directory.
        """
        template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate(self, payload_type, target_os, ip, port, language=None, ssl=False, anti_analysis=False, **kwargs):
        """
        Generate a payload based on type, OS, and connection details.

        Args:
            payload_type (str): Type of payload (e.g., 'reverse-shell').
            target_os (str): Target Operating System (e.g., 'linux', 'windows').
            ip (str): Attacker IP address.
            port (str): Attacker listening port.
            language (str): Optional language override (e.g., 'go', 'c').
            ssl (bool): Use SSL/TLS.
            anti_analysis (bool): Add anti-analysis/sandbox checks.
            **kwargs: Additional variables for templates (e.g., token, kill_date, geofence).

        Returns:
            str: Generated source code.
        
        Raises:
            ValueError: If the template for the requested combination is not found.
        """
        # Map OS to default file extension/language
        extensions = {
            'linux': 'bash',
            'windows': 'ps1',
            'web': 'js',
            'c': 'c'
        }

        if language:
            ext = language
        elif target_os in extensions:
            ext = extensions[target_os]
        else:
            # Fallback or error
            ext = target_os

        # Template naming convention: type.ext.j2
        # We need to handle special cases where payload_type implies a specific file name structure
        # or where the extension logic needs refinement.
        
        normalized_type = payload_type.replace('-', '_')
        
        # Specific mappings for new payload types if they deviate from type.ext.j2
        # However, we named files to match: shell_reverse.rs.j2, web_shell.php.j2 etc.
        # If user passes type='shell-reverse' and lang='rs', result is 'shell_reverse.rs.j2' (Correct)
        # If user passes type='web-shell' and lang='php', result is 'web_shell.php.j2' (Correct)
        
        # Mapping for 'persistence' generic type to specific files based on OS
        if payload_type == 'persistence':
            if target_os == 'linux':
                normalized_type = 'persist_suid'
                ext = 'c'
            elif target_os == 'windows':
                normalized_type = 'persist_reg'
                ext = 'ps1'
        
        # Mapping for specific new shells to match provided filenames
        if payload_type == 'bind-shell':
            normalized_type = 'shell_bind'
        elif payload_type == 'conpty-shell':
            normalized_type = 'shell_conpty'
        elif payload_type == 'inject':
            normalized_type = 'inject_shellcode'
            # Default to C if not specified, though logic below sets default extension based on OS
            # If OS is windows, default is ps1, but we want C or Py for injection templates provided
            if language is None and target_os == 'windows':
                ext = 'c' # Default to C for injection
        
        # Handle Rust/Go Reverse Shell naming divergence if any
        # Existing: reverse_shell.bash.j2
        # New: shell_reverse.rs.j2, shell_reverse.go.j2
        if payload_type == 'reverse-shell' and ext in ['rs', 'go']:
            normalized_type = 'shell_reverse'

        template_name = f"{normalized_type}.{ext}.j2"
        
        try:
            template = self.env.get_template(template_name)
        except Exception:
            raise ValueError(f"Template not found for {payload_type} on {target_os} (lang={ext})")

        # Pass specific params if available (we might need to extend generate signature later or assume default)
        return template.render(ip=ip, port=port, ssl=ssl, anti_analysis=anti_analysis, **kwargs)

    def generate_stub(self, language, ciphertext, key, iv, guardrail=None, kill_date=None, geofence=None, target_os=None, **kwargs):
        """
        Generate a loader/stub that decrypts and executes the payload.
        """
        if target_os == 'windows' and language == 'c':
            template_name = "stub_windows.c.j2"
        else:
            template_name = f"stub.{language}.j2"
            
        try:
            template = self.env.get_template(template_name)
        except Exception:
             # Fallback if no specific stub, try python? No.
             raise ValueError(f"Stub template not found for {language}")
        
        # Pass kwargs to handle extra params like kill_date_ts
        return template.render(ciphertext=ciphertext, key=key, iv=iv, guardrail=guardrail, kill_date=kill_date, geofence=geofence, ip="1.1.1.1", port=1337, **kwargs)
