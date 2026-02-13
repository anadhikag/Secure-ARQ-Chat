import socket
import threading
import time
import random
import struct
import binascii
import os
from enum import Enum
from typing import Dict, List, Tuple

# ================================================================
# CONFIGURATION
# ================================================================
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
MAX_BUFFER_SIZE = 4096
TIMEOUT_INTERVAL = 2.0  # Stop-and-Wait timeout (seconds)

class NetConfig:
    LOSS_RATE = 0.1          # Simulated packet loss
    WINDOW_SIZE = 1          # Fixed to 1 (Stop-and-Wait)
    ENCRYPTION_ENABLED = True


# ================================================================
# APPLICATION LAYER: END-TO-END ENCRYPTION
# ================================================================
class CryptoManager:
    """
    Lightweight symmetric encryption to demonstrate
    end-to-end encryption placement in the protocol stack.
    """

    @staticmethod
    def _derive_key(channel_id: str) -> bytes:
        return binascii.hexlify(channel_id.encode())[:16]

    @staticmethod
    def encrypt(plaintext: str, channel_id: str) -> bytes:
        if not NetConfig.ENCRYPTION_ENABLED:
            return plaintext.encode()

        key = CryptoManager._derive_key(channel_id)
        return bytes(
            ord(plaintext[i]) ^ key[i % len(key)]
            for i in range(len(plaintext))
        )

    @staticmethod
    def decrypt(ciphertext: bytes, channel_id: str) -> str:
        if not NetConfig.ENCRYPTION_ENABLED:
            return ciphertext.decode()

        key = CryptoManager._derive_key(channel_id)
        decrypted = bytes(
            ciphertext[i] ^ key[i % len(key)]
            for i in range(len(ciphertext))
        )
        return decrypted.decode()


# ================================================================
# DATA LINK LAYER: FRAMING + CRC
# ================================================================
class FrameType(Enum):
    DATA = 0
    ACK = 1
    JOIN = 2
    CREATE = 3


class ProtocolHandler:
    """
    Frame Format (Big Endian):
    [ChannelID: 3 bytes] [Type: 1 byte] [Seq No: 4 bytes] [CRC: 2 bytes] [Payload: variable]
    """
    HEADER_FORMAT = "!3sBIH"

    @staticmethod
    def compute_crc(data: bytes) -> int:
        return binascii.crc_hqx(data, 0xFFFF)

    @staticmethod
    def create_frame(channel_id: str, frame_type: FrameType, seq_no: int, payload: bytes) -> bytes:
        channel_bytes = binascii.unhexlify(channel_id)
        crc = ProtocolHandler.compute_crc(payload)
        header = struct.pack(ProtocolHandler.HEADER_FORMAT, channel_bytes, frame_type.value, seq_no, crc)
        return header + payload

    @staticmethod
    def parse_frame(frame: bytes) -> Tuple[str, FrameType, int, bytes]:
        header_size = struct.calcsize(ProtocolHandler.HEADER_FORMAT)
        if len(frame) < header_size:
            raise ValueError("Frame too short")

        header = frame[:header_size]
        payload = frame[header_size:]

        channel_bytes, f_type, seq_no, recv_crc = struct.unpack(ProtocolHandler.HEADER_FORMAT, header)
        actual_crc = ProtocolHandler.compute_crc(payload)
        if actual_crc != recv_crc:
            raise ValueError("CRC mismatch")

        channel_id = binascii.hexlify(channel_bytes).decode().upper()
        return channel_id, FrameType(f_type), seq_no, payload


# ================================================================
# NETWORK LAYER: RELAY SERVER
# ================================================================
class RelayServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((SERVER_IP, SERVER_PORT))
        self.channels: Dict[str, List[tuple]] = {}
        self.running = True

    def start(self):
        print(f"[SERVER] Running on {SERVER_IP}:{SERVER_PORT}")
        while self.running:
            try:
                frame, sender = self.sock.recvfrom(MAX_BUFFER_SIZE)
                if random.random() < NetConfig.LOSS_RATE:
                    print(f"[SIM] Dropped packet from {sender}")
                    continue

                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(frame)

                if f_type == FrameType.CREATE:
                    new_id = binascii.hexlify(os.urandom(3)).decode().upper()
                    self.channels[new_id] = [sender]
                    response = ProtocolHandler.create_frame(new_id, FrameType.CREATE, 0, b"CREATED")
                    self.sock.sendto(response, sender)
                    print(f"[SERVER] Channel {new_id} created by {sender}")

                elif f_type == FrameType.JOIN:
                    if channel_id in self.channels:
                        if sender not in self.channels[channel_id]:
                            self.channels[channel_id].append(sender)
                        response = ProtocolHandler.create_frame(channel_id, FrameType.JOIN, 0, b"JOINED")
                        self.sock.sendto(response, sender)
                        print(f"[SERVER] {sender} joined {channel_id}")
                    else:
                        print(f"[SERVER] Join failed for {channel_id}")

                elif f_type in (FrameType.DATA, FrameType.ACK):
                    if channel_id in self.channels:
                        for target in self.channels[channel_id]:
                            if target != sender:
                                self.sock.sendto(frame, target)
                                print(f"[RELAY] {channel_id} Seq={seq} Type={f_type.name} -> {target}")
            except Exception as e:
                print(f"[SERVER ERROR] {e}")


# ================================================================
# CLIENT: STOP-AND-WAIT ARQ
# ================================================================
class ARQClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.channel_id = "000000"
        self.send_seq = 0
        self.expected_seq = 0
        self.ack_event = threading.Event()
        self.last_ack = -1
        self.running = True

    def _print_ui(self, message: str = ""):
        """Helper to clear line and reprint prompt to keep UI clean."""
        # \r moves cursor to start of line, \033[K clears the line
        print(f"\r\033[K{message}\n[{self.channel_id}] > ", end="", flush=True)

    def receiver(self):
        while self.running:
            try:
                frame, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)
                channel_id, f_type, seq, payload = ProtocolHandler.parse_frame(frame)

                if f_type in (FrameType.CREATE, FrameType.JOIN):
                    self.channel_id = channel_id
                    self._print_ui(f"[SYSTEM] Connected to Channel {channel_id}")

                elif f_type == FrameType.ACK:
                    self.last_ack = seq
                    self.ack_event.set()
                    # Optionally show ACK received
                    # self._print_ui(f"[ACK] Received for Seq {seq}")

                elif f_type == FrameType.DATA:
                    if seq == self.expected_seq:
                        message = CryptoManager.decrypt(payload, self.channel_id)
                        self._print_ui(f"[MSG] {message}")
                        ack = ProtocolHandler.create_frame(self.channel_id, FrameType.ACK, seq, b"ACK")
                        self.sock.sendto(ack, (SERVER_IP, SERVER_PORT))
                        self.expected_seq += 1
                    else:
                        # Duplicate frame due to lost ACK
                        self._print_ui(f"[RCV] Duplicate/Out-of-order Seq {seq}. Discarding.")
                        if self.expected_seq > 0:
                            ack = ProtocolHandler.create_frame(self.channel_id, FrameType.ACK, seq, b"ACK")
                            self.sock.sendto(ack, (SERVER_IP, SERVER_PORT))

            except Exception:
                continue

    def send_message(self, text: str):
        payload = CryptoManager.encrypt(text, self.channel_id)
        seq = self.send_seq
        frame = ProtocolHandler.create_frame(self.channel_id, FrameType.DATA, seq, payload)

        while True:
            self.ack_event.clear()
            self.sock.sendto(frame, (SERVER_IP, SERVER_PORT))
            print(f"[SEND] Seq {seq}")

            if self.ack_event.wait(TIMEOUT_INTERVAL):
                if self.last_ack >= seq:
                    self.send_seq += 1
                    return
            print(f"[TIMEOUT] Retransmitting Seq {seq}")

    def ui(self):
        threading.Thread(target=self.receiver, daemon=True).start()
        print("Commands: CREATE | JOIN <id> | SEND <msg> | SET LOSS <val> | EXIT")
        while self.running:
            try:
                user_input = input(f"[{self.channel_id}] > ").strip()
                if not user_input: continue
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "CREATE":
                    f = ProtocolHandler.create_frame("000000", FrameType.CREATE, 0, b"")
                    self.sock.sendto(f, (SERVER_IP, SERVER_PORT))
                elif cmd == "JOIN":
                    f = ProtocolHandler.create_frame(arg.upper(), FrameType.JOIN, 0, b"")
                    self.sock.sendto(f, (SERVER_IP, SERVER_PORT))
                elif cmd == "SEND":
                    if self.channel_id == "000000": print("Error: No channel joined.")
                    else: self.send_message(arg)
                elif cmd == "SET":
                    subparts = arg.split()
                    if len(subparts) == 2 and subparts[0].upper() == "LOSS":
                        NetConfig.LOSS_RATE = float(subparts[1])
                        print(f"Loss rate: {NetConfig.LOSS_RATE}")
                elif cmd == "EXIT":
                    self.running = False
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1].lower() == "server":
        RelayServer().start()
    else:
        ARQClient().ui()