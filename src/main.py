import argparse
import sys
import os
import asyncio

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.engine import PayloadEngine
from core.c2 import C2Server

def main():
    parser = argparse.ArgumentParser(description="Multi-Language Offensive Security Toolkit (CLI)")
    parser.add_argument("--sim", action="store_true", help="Enable simulation mode (dry-run)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # 'gen' command
    gen = subparsers.add_parser("gen", help="Generate a payload")
    gen.add_argument("--type", required=True, help="Type of payload")
    gen.add_argument("--os", required=True, choices=["linux", "windows", "web", "c"], help="Target OS")
    gen.add_argument("--ip", required=True, help="LHOST")
    gen.add_argument("--port", required=True, help="LPORT")
    gen.add_argument("--lang", help="Payload language")
    gen.add_argument("--ssl", action="store_true", help="Use SSL")
    gen.add_argument("--token", help="Auth token")
    gen.add_argument("--obfuscate", choices=["none", "low", "medium", "high"], default="none", help="Obfuscation")
    gen.add_argument("--encrypt", action="store_true", help="Encrypt payload")
    gen.add_argument("--guardrail", help="Env Guardrail (e.g., USERNAME)")
    gen.add_argument("--kill-date", help="Kill Date (YYYY-MM-DD)")
    gen.add_argument("--geofence", help="Geofence Country Code (e.g., US)")
    gen.add_argument("--anti-analysis", action="store_true", help="Anti-Analysis")
    gen.add_argument("--process", help="Target Process")
    gen.add_argument("--target-pid", help="Target PID")
    gen.add_argument("--out", help="Output file")
    gen.add_argument("--delivery", choices=["file", "email", "web"], default="file", help="Delivery method")

    # 'listen' command
    listen = subparsers.add_parser("listen", help="Start a listener")
    listen.add_argument("--port", required=True, help="Port")
    listen.add_argument("--protocol", choices=["tcp", "udp", "http", "dns"], default="tcp", help="Protocol")
    listen.add_argument("--ssl", action="store_true", help="Use SSL")

    args = parser.parse_args()

    if args.command == "listen":
        server = C2Server()
        try:
            asyncio.run(server.start_server(args.port, args.protocol))
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
    elif args.command == "gen":
        engine = PayloadEngine()
        engine.generate_payload(args.type, args.os, args.ip, args.port, args.lang, args.ssl, 
                                args.token, args.obfuscate, args.encrypt, args.guardrail, 
                                args.kill_date, args.geofence,
                                args.anti_analysis, args.process, args.target_pid, 
                                args.delivery, args.out, args.sim, args.verbose)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
