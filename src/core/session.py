import asyncio

class Session:
    def __init__(self, id, reader, writer, addr, transport="tcp"):
        self.id = id
        self.reader = reader # Can be None for HTTP/DNS
        self.writer = writer # Can be None for HTTP/DNS
        self.addr = addr
        self.transport = transport
        self.active = True
        self.info = {}
        
        # For Polling Transports (HTTP/DNS)
        self.cmd_queue = asyncio.Queue()
        self.output_queue = asyncio.Queue() # Output from agent
    
    async def send(self, data):
        if self.transport == "tcp" and self.writer:
            self.writer.write(data.encode())
            await self.writer.drain()
        else:
            # Queue for polling
            await self.cmd_queue.put(data)

    async def read(self):
        """
        Reads data. For TCP, reads from socket.
        For Polling, reads from output_queue.
        """
        if self.transport == "tcp" and self.reader:
            return await self.reader.read(4096)
        else:
            return await self.output_queue.get()

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.counter = 0

    def create_session(self, reader, writer, addr, transport="tcp"):
        self.counter += 1
        sid = self.counter
        session = Session(sid, reader, writer, addr, transport)
        self.sessions[sid] = session
        return session
    
    def get_session(self, sid):
        return self.sessions.get(sid)
    
    def remove_session(self, sid):
        if sid in self.sessions:
            del self.sessions[sid]
