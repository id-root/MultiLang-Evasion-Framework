import sys
import subprocess
import shutil
import socket
import threading
import ssl as ssl_lib
import http.server
import socketserver

class Listener:
    """
    Handles starting listeners for payloads.
    """

    def start(self, port, protocol="tcp", use_ssl=False):
        """
        Start a listener on the specified port.
        
        Args:
            port (int): Port to listen on.
            protocol (str): 'tcp', 'udp', 'http', or 'dns'.
            use_ssl (bool): Whether to use SSL/TLS.
        """
        print(f"[*] Starting {protocol.upper()} listener on port {port} (SSL={use_ssl})...")

        if protocol == "http":
            self._start_http_listener(port)
        elif protocol == "dns":
            self._start_dns_responder(port)
        elif use_ssl:
            self._start_ssl_listener(port)
        else:
            self._start_simple_listener(port, protocol)

    def _start_http_listener(self, port):
        """
        Starts a simple HTTP server.
        """
        Handler = http.server.SimpleHTTPRequestHandler
        try:
            with socketserver.TCPServer(("", int(port)), Handler) as httpd:
                print(f"[*] Serving HTTP on 0.0.0.0 port {port} ...")
                httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopped.")

    def _start_dns_responder(self, port):
        """
        Starts a simple mocked DNS responder (UDP).
        """
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(("", int(port)))
        print(f"[*] DNS Responder listening on 0.0.0.0:{port} ...")
        
        try:
            while True:
                data, addr = udps.recvfrom(1024)
                print(f"[DNS Query from {addr}] {data}")
                # Mock response?
                # Just printing for now as per "mocked DNS responder"
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
        finally:
            udps.close()

    def _start_ssl_listener(self, port):
        """
        Start an SSL listener using socat or openssl if available, else Python.
        """
        if shutil.which("socat"):
            # socat file:`tty`,raw,echo=0 openssl-listen:<port>,cert=cert.pem,verify=0
            # For simplicity, we assume a cert exists or generate one? 
            # Generating a self-signed cert on the fly is best practice but complex in a one-liner.
            # Using python is easier for SSL if we can generate a cert.
            # But let's try to use ncat (nmap cat) which supports --ssl if available.
            pass

        # Fallback to Python implementation for reliability
        self._start_python_ssl_listener(port)

    def _start_simple_listener(self, port, protocol):
        """
        Start a simple listener using netcat or Python.
        """
        nc_cmd = shutil.which("nc") or shutil.which("ncat")
        if nc_cmd and protocol == "tcp":
            print(f"[+] Using {nc_cmd}")
            subprocess.run([nc_cmd, "-lvnp", str(port)])
        else:
            self._start_python_listener(port, protocol)

    def _start_python_listener(self, port, protocol):
        """
        Pure Python TCP/UDP listener.
        """
        print("[*] Using Python fallback listener")
        sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        s = socket.socket(socket.AF_INET, sock_type)
        s.bind(("0.0.0.0", int(port)))
        
        if protocol == "tcp":
            s.listen(1)
            print(f"[*] Listening on 0.0.0.0:{port}...")
            conn, addr = s.accept()
            print(f"[+] Connection from {addr}")
            self._handle_connection(conn)
        else:
            print(f"[*] Listening on UDP 0.0.0.0:{port}...")
            while True:
                data, addr = s.recvfrom(4096)
                print(f"[{addr}] {data.decode(errors='replace')}")

    def _start_python_ssl_listener(self, port):
        """
        Pure Python SSL listener.
        Generates a temporary self-signed cert.
        """
        print("[*] Generating temporary self-signed cert for SSL listener...")
        # We need to generate a cert using openssl or pure python (crypto library).
        # Since we might not have crypto lib yet (Phase 4), lets try openssl command.
        
        cert_file = "temp_cert.pem"
        key_file = "temp_key.pem"
        
        if shutil.which("openssl"):
            subprocess.run(
                ["openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "365", "-nodes", "-x509", 
                 "-keyout", key_file, "-out", cert_file, "-subj", "/CN=localhost"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            print("[-] OpenSSL not found. Cannot start SSL listener without certificate.")
            return

        context = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.bind(('0.0.0.0', int(port)))
        s.listen(1)
        
        with context.wrap_socket(s, server_side=True) as ssock:
            print(f"[*] SSL Listening on 0.0.0.0:{port}...")
            conn, addr = ssock.accept()
            print(f"[+] SSL Connection from {addr}")
            self._handle_connection(conn)
        
        # Cleanup
        if os.path.exists(cert_file): os.remove(cert_file)
        if os.path.exists(key_file): os.remove(key_file)

    def _handle_connection(self, conn):
        """
        Handle the connection (read/write loop).
        """
        def listen_socket():
            while True:
                data = conn.recv(1024)
                if not data: break
                sys.stdout.write(data.decode(errors='replace'))
                sys.stdout.flush()
        
        t = threading.Thread(target=listen_socket)
        t.daemon = True
        t.start()
        
        try:
            while True:
                cmd = sys.stdin.readline()
                conn.send(cmd.encode())
        except KeyboardInterrupt:
            conn.close()
            print("\n[*] Connection closed.")
