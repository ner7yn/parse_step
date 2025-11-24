import socket
import threading
import logging
import binascii
import struct

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class GalileoSKYTCPServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
    
    def calculate_crc(self, data: bytes) -> int:
        """Вычисление CRC16 для пакета"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc
    
    def create_response(self, packet_id: int = 0) -> bytes:
        """Создает корректный ответ для устройства"""
        response = b'\x00\x01'  # Префикс
        response += b'\x00\x02'  # Длина пакета
        response += packet_id.to_bytes(2, 'big')  # ID пакета
        response += b'\x00'     # Флаги (успех)
        
        # Вычисляем CRC
        crc = self.calculate_crc(response)
        response += crc.to_bytes(2, 'little')  # Little-endian CRC
        
        return response
    
    def parse_galileo_packet(self, data: bytes):
        """Парсит пакет GalileoSKY"""
        try:
            if len(data) < 10:
                return {"error": "Packet too short"}
            
            # Проверяем префикс
            if data[0] != 0x00 or data[1] != 0x01:
                return {"error": "Invalid prefix"}
            
            # Длина пакета
            length = struct.unpack('>H', data[2:4])[0]
            
            # ID пакета
            packet_id = struct.unpack('>H', data[4:6])[0]
            
            # Флаги
            flags = data[6]
            
            # Полезная нагрузка
            payload = data[7:-2] if len(data) > 8 else b''
            
            # CRC
            received_crc = struct.unpack('<H', data[-2:])[0]  # Little-endian
            
            return {
                "length": length,
                "packet_id": packet_id,
                "flags": flags,
                "payload_length": len(payload),
                "payload_hex": binascii.hexlify(payload).decode(),
                "received_crc": received_crc,
                "valid": True
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def handle_client(self, conn, addr):
        """Обработка подключения устройства"""
        logger.info(f"🔌 New connection from {addr}")
        
        try:
            while True:
                # Получаем бинарные данные по TCP
                data = conn.recv(4096)
                if not data:
                    logger.info(f"🔌 Connection closed by {addr}")
                    break
                
                logger.info(f"📨 Received {len(data)} bytes from {addr}")
                hex_data = binascii.hexlify(data).upper().decode()
                logger.info(f"🔧 Hex data: {hex_data}")
                
                # Парсим пакет
                packet_info = self.parse_galileo_packet(data)
                
                if packet_info.get("valid"):
                    logger.info(f"📋 Valid packet: ID={packet_info['packet_id']}")
                    logger.info(f"📦 Payload: {packet_info['payload_hex']}")
                    
                    # Создаем ответ
                    response = self.create_response(packet_info['packet_id'])
                    
                    logger.info(f"📤 Sending response: {binascii.hexlify(response).upper().decode()}")
                    
                    # Отправляем ответ
                    conn.send(response)
                    logger.info("✅ Successfully processed packet")
                    
                else:
                    logger.warning(f"⚠️ Invalid packet: {packet_info.get('error')}")
                    # Все равно отправляем ответ
                    response = self.create_response()
                    conn.send(response)
                    
        except ConnectionResetError:
            logger.info(f"🔌 Connection reset by {addr}")
        except Exception as e:
            logger.error(f"💥 Error with {addr}: {e}")
        finally:
            conn.close()
            logger.info(f"🔌 Connection closed with {addr}")
    
    def start(self):
        """Запуск TCP сервера"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                
                logger.info("🚀 " + "="*50)
                logger.info(f"📍 GalileoSKY TCP Server started successfully!")
                logger.info(f"📍 Listening on: {self.host}:{self.port}")
                logger.info("📍 Protocol: TCP (binary GalileoSKY)")
                logger.info("🚀 " + "="*50)
                logger.info("📡 Waiting for device connections...")
                
                while True:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
        except Exception as e:
            logger.error(f"💥 Failed to start server: {e}")

if __name__ == "__main__":
    server = GalileoSKYTCPServer()
    server.start()