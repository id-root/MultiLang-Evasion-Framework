import json
import datetime
import os
import re

class Reporter:
    """
    Handles logging and reporting of actions.
    """

    def log(self, data):
        """
        Log data to a JSON file.
        
        Args:
            data (dict): Data to log.
        """
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            **data
        }
        
        log_file = "activity.log"
        
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
        print(f"[+] Action logged to {log_file}")

    def generate_yara_rule(self, data, payload_content):
        """
        Generate a YARA rule for the generated payload.
        
        Args:
            data (dict): Metadata.
            payload_content (bytes or str): The payload content.
        """
        if not payload_content:
            return

        rule_name = f"multilang_{data['type']}_{data['os']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)

        # Extract strings
        content_str = ""
        if isinstance(payload_content, bytes):
            try:
                content_str = payload_content.decode('utf-8', errors='ignore')
            except:
                pass
        else:
            content_str = payload_content

        # Find ASCII strings > 5 chars
        strings_found = re.findall(r'[ -~]{6,}', content_str)
        
        # Filter strings (remove too short or common)
        # We also definitely want to detect the C2 IP/Port if visible
        target_strings = []
        if data.get('ip'):
            target_strings.append(f'"{data["ip"]}"')
        
        # Add some random unique strings found in payload
        # Sort by length desc
        strings_found.sort(key=len, reverse=True)
        for s in strings_found[:5]:
            # Escape quotes
            s_esc = s.replace('\\', '\\\\').replace('"', '\\"')
            target_strings.append(f'"{s_esc}"')

        # If binary, add some hex bytes from entry point or start
        hex_string = ""
        if isinstance(payload_content, bytes) and len(payload_content) > 16:
             # Take 16 bytes from offset 0
             hex_bytes = payload_content[:16].hex()
             # Format for YARA: { XX XX ... }
             hex_string = "{ " + " ".join([hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]) + " }"

        # Build Rule
        rule = f"""rule {rule_name} {{
    meta:
        author = "MultiLangPayloadCLI"
        date = "{datetime.date.today()}"
        description = "Auto-generated rule for {data['type']} on {data['os']}"
        c2_ip = "{data.get('ip', 'N/A')}"
        hash = "{hash(payload_content)}"

    strings:
"""
        i = 0
        for s in set(target_strings):
            rule += f"        $s{i} = {s}\n"
            i += 1
        
        if hex_string:
            rule += f"        $h1 = {hex_string}\n"

        rule += """
    condition:
        all of them
}"""
        
        report_dir = "reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        rule_file = os.path.join(report_dir, "generated_rule.yar")
        
        # Append to rule file
        with open(rule_file, "a") as f:
            f.write(rule + "\n\n")
            
        print(f"[+] YARA rule generated: {rule_file}")
