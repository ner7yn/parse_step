import socket
import threading
import logging
import binascii
import struct

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class GalileoSKYServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
    
    def calculate_crc16_ccitt(self, data: bytes) -> int:
        """CRC16-CCITT (используется в GalileoSKY)"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc = crc << 1
                crc &= 0xFFFF
        return crc
    
    def calculate_crc16_modbus(self, data: bytes) -> int:
        """CRC16 MODBUS"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc
    
    def calculate_crc16_kermit(self, data: bytes) -> int:
        """CRC16 Kermit"""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
        return crc
    
    def create_galileosky_response(self, packet_id: int = 0) -> bytes:
        """Создает ответ и тестирует разные CRC"""
        # Базовый ответ
        response_base = b'\x00\x01'  # Префикс
        response_base += b'\x00\x02'  # Длина пакета
        response_base += packet_id.to_bytes(2, 'big')  # ID пакета
        response_base += b'\x00'     # Флаги (успех)
        
        # Тестируем разные алгоритмы CRC
        crc_ccitt = self.calculate_crc16_ccitt(response_base)
        crc_modbus = self.calculate_crc16_modbus(response_base)
        crc_kermit = self.calculate_crc16_kermit(response_base)
        
        logger.info(f"🔢 CRC tests: CCITT={crc_ccitt:04X}, MODBUS={crc_modbus:04X}, Kermit={crc_kermit:04X}")
        
        # Пробуем CCITT (самый вероятный для GalileoSKY)
        response = response_base + crc_ccitt.to_bytes(2, 'big')
        
        return response
    
    def parse_custom_packet(self, data: bytes):
        """Парсим кастомный пакет трекера"""
        result = {
            "raw_hex": binascii.hexlify(data).upper().decode(),
            "length": len(data),
            "imei": None,
            "packet_id": 0
        }
        
        try:
            # Извлекаем IMEI
            if b'867994064255157' in data:
                result["imei"] = "867994064255157"
            
            # Извлекаем ID пакета из структуры 01218001...
            if len(data) >= 4:
                potential_id = struct.unpack('>H', data[2:4])[0]
                result["packet_id"] = potential_id
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Parse error: {e}")
            return result
    
    def handle_client(self, conn, addr):
        """Обработка подключения устройства"""
        logger.info(f"🔌 New connection from {addr}")
        
        try:
            data = conn.recv(4096)
            if not data:
                return
            
            logger.info(f"📨 Received {len(data)} bytes")
            logger.info(f"🔧 Hex: {binascii.hexlify(data).upper().decode()}")
            
            # Определяем тип пакета
            if data.startswith(b'\x01\x21'):  # Кастомный протокол трекера
                logger.info("📋 Protocol: Custom tracker -> converting to GalileoSKY response")
                packet_info = self.parse_custom_packet(data)
                logger.info(f"🆔 Packet ID: {packet_info['packet_id']}")
                
                # Создаем ответ
                response = self.create_galileosky_response(packet_info["packet_id"])
                logger.info(f"📤 Sending response: {binascii.hexlify(response).upper().decode()}")
                
            elif data.startswith(b'\x00\x01'):  # Уже GalileoSKY
                logger.info("📋 Protocol: Native GalileoSKY")
                packet_id = struct.unpack('>H', data[4:6])[0] if len(data) >= 6 else 0
                response = self.create_galileosky_response(packet_id)
                logger.info(f"📤 Sending response: {binascii.hexlify(response).upper().decode()}")
                
            else:
                logger.info("📋 Protocol: Unknown")
                response = b'\x01\x00\x01'
            
            # Отправляем ответ
            conn.send(response)
            logger.info("✅ Response sent")
            
        except Exception as e:
            logger.error(f"💥 Error: {e}")
        finally:
            conn.close()
            logger.info(f"🔌 Connection closed")
    
    def start(self):
        """Запуск сервера"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                
                logger.info("🚀 " + "="*60)
                logger.info(f"📍 GalileoSKY Server with CRC testing")
                logger.info(f"📍 Listening on: {self.host}:{self.port}")
                logger.info("🚀 " + "="*60)
                
                while True:
                    conn, addr = s.accept()
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                    
        except Exception as e:
            logger.error(f"❌ Server error: {e}")

if __name__ == "__main__":
    server = GalileoSKYServer()
    server.start()