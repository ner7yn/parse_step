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
    
    def calculate_crc16_galileo(self, data: bytes) -> int:
        """CRC16 для протокола GalileoSKY"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc
    
    def create_galileosky_response(self, packet_id: int = 0) -> bytes:
        """Создает КОРРЕКТНЫЙ ответ в формате GalileoSKY"""
        # Стандартный ответ GalileoSKY
        response = b'\x00\x01'  # Префикс
        response += b'\x00\x02'  # Длина пакета
        response += packet_id.to_bytes(2, 'big')  # ID пакета (из входящего)
        response += b'\x00'     # Флаги (успех)
        
        # Вычисляем CRC (big-endian для GalileoSKY)
        crc = self.calculate_crc16_galileo(response)
        response += crc.to_bytes(2, 'big')
        
        return response
    
    def parse_custom_packet(self, data: bytes):
        """Парсим кастомный пакет трекера"""
        hex_data = binascii.hexlify(data).upper().decode()
        
        result = {
            "raw_hex": hex_data,
            "length": len(data),
            "imei": None,
            "packet_id": 0
        }
        
        try:
            # Извлекаем IMEI
            if b'867994064255157' in data:
                result["imei"] = "867994064255157"
            
            # Пытаемся извлечь ID пакета из структуры 01218001...
            if len(data) >= 4:
                # Первые 4 байта: 01218001
                # Возможно 8001 - это ID пакета
                potential_id = struct.unpack('>H', data[2:4])[0]
                result["packet_id"] = potential_id
                logger.info(f"🆔 Potential packet ID: {potential_id}")
            
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
                
                # Создаем ПРАВИЛЬНЫЙ ответ GalileoSKY
                response = self.create_galileosky_response(packet_info["packet_id"])
                logger.info(f"📤 Sending GalileoSKY response: {binascii.hexlify(response).upper().decode()}")
                
            elif data.startswith(b'\x00\x01'):  # Уже GalileoSKY
                logger.info("📋 Protocol: Native GalileoSKY")
                # Извлекаем ID пакета
                packet_id = struct.unpack('>H', data[4:6])[0] if len(data) >= 6 else 0
                response = self.create_galileosky_response(packet_id)
                logger.info(f"📤 Sending GalileoSKY response: {binascii.hexlify(response).upper().decode()}")
                
            else:  # HTTP или неизвестный протокол
                logger.info("📋 Protocol: HTTP or unknown - sending generic response")
                response = b'\x01\x00\x01'  # Простой ответ
            
            # Отправляем ответ
            conn.send(response)
            logger.info(f"✅ Response sent successfully")
            
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
                logger.info(f"📍 GalileoSKY Protocol Server started!")
                logger.info(f"📍 Listening on: {self.host}:{self.port}")
                logger.info("📍 Converts custom protocol to GalileoSKY responses")
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