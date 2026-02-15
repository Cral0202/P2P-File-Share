import threading
import json
import struct
import queue
import ssl

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .network import Network

class ConnectionHandler(threading.Thread):
    def __init__(self, sock: ssl.SSLSocket, network: Network, is_outbound: bool):
        super().__init__(daemon = True)

        self.sock: ssl.SSLSocket = sock
        self.network: Network = network
        self.is_outbound: bool = is_outbound
        self.accepted_conn: bool = False

        self.running: bool = True
        self.send_queue: queue.Queue = queue.Queue(maxsize = 5)

    def run(self):
        reader = threading.Thread(target = self._recv_loop, daemon = True)
        reader.start()

        self._send_loop()

    def send(self, msg_type: str, data: str = "", raw_data: bytes = b""):
        # Prepare JSON header
        header_dict = {"type": msg_type, "data": data}
        header_bytes = json.dumps(header_dict).encode()

        # Structure: [4-byte JSON len][JSON][Raw Binary]
        # Pack the length of the JSON part so the receiver knows when to stop reading text
        envelope = struct.pack('>I', len(header_bytes)) + header_bytes + raw_data

        self.send_queue.put(envelope)

    def _send_loop(self):
        while self.running:
            try:
                msg = self.send_queue.get()

                # Flush and stop message
                if msg is None:
                    self.stop()
                    break

                self.network.send_msg(self.sock, msg)
            except Exception:
                self.stop()

    def _recv_loop(self):
        while self.running:
            try:
                blob = self.network.recv_msg(self.sock)

                # Read the first 4 bytes of the blob to get the JSON header length
                header_len = struct.unpack('>I', blob[:4])[0]
                header_json = blob[4 : 4 + header_len].decode()
                msg = json.loads(header_json)

                # The rest of the blob is raw binary data
                raw_payload = blob[4 + header_len:]

                self.network.handle_incoming_message(self, msg.get("type"), msg.get("data"), raw_payload)
            except Exception:
                self.stop()

    def stop(self):
        self.running = False
        self.network._close_socket(self.sock)
        self.network._handle_connection_error(self.is_outbound)

    def flush_and_stop(self):
        self.send_queue.put(None)
