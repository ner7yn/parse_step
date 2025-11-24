import socket
import threading
import logging
import binascii

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GalileoSKYServer:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
    
    def calculate_crc(self, data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc
    
    def create_response(self, packet_id=0):
        response = b'\x00\x01\x00\x02'
        response += packet_id.to_bytes(2, 'big')
        response += b'\x00'
        
        crc = self.calculate_crc(response)
        response += crc.to_bytes(2, 'little')
        return response
    
    def handle_client(self, conn, addr):
        logger.info(f"🎉 CONNECTED from {addr}")
        
        try:
            data = conn.recv(1024)
            if data:
                logger.info(f"📨 Received {len(data)} bytes")
                logger.info(f"🔧 Hex: {binascii.hexlify(data).upper().decode()}")
                
                packet_id = 0
                if len(data) >= 6:
                    packet_id = int.from_bytes(data[4:6], 'big')
                    logger.info(f"🆔 Packet ID: {packet_id}")
                
                response = self.create_response(packet_id)
                conn.send(response)
                logger.info(f"📤 Response: {binascii.hexlify(response).upper().decode()}")
                logger.info("✅ SUCCESS! Device connected!")
            
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            conn.close()
    
    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                
                logger.info(f"🚀 Server started on {self.host}:{self.port}")
                logger.info("📡 Waiting for Serveo tunnel...")
                
                while True:
                    conn, addr = s.accept()
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                    
        except Exception as e:
            logger.error(f"Server error: {e}")

if __name__ == "__main__":
    server = GalileoSKYServer('localhost', 8000)
    server.start()