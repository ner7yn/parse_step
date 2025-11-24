import socket
import threading
import logging
import binascii
import struct
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class UniversalTrackerServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
    
    def calculate_crc(self, data: bytes) -> int:
        """Вычисление CRC16"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc
    
    def create_galileosky_response(self, packet_id: int = 0) -> bytes:
        """Создает ответ в формате GalileoSKY"""
        response = b'\x00\x01'  # Префикс
        response += b'\x00\x02'  # Длина
        response += packet_id.to_bytes(2, 'big')  # ID пакета
        response += b'\x00'     # Флаги
        
        crc = self.calculate_crc(response)
        response += crc.to_bytes(2, 'little')
        return response
    
    def create_generic_response(self) -> bytes:
        """Создает универсальный подтверждающий ответ"""
        # Простой ответ "OK" в бинарном формате
        return b'\x01\x02\x00\x01'  # Базовый подтверждающий пакет
    
    def parse_unknown_protocol(self, data: bytes):
        """Пытается распарсить неизвестный протокол"""
        hex_data = binascii.hexlify(data).upper().decode()
        logger.info(f"🔍 Analyzing unknown protocol data:")
        logger.info(f"   Full HEX: {hex_data}")
        logger.info(f"   Length: {len(data)} bytes")
        
        # Анализируем структуру
        if len(data) >= 4:
            logger.info(f"   First 4 bytes: {binascii.hexlify(data[:4]).decode()}")
        
        # Пытаемся найти IMEI в данных
        if b'867994064255157' in data:
            imei_pos = data.find(b'867994064255157')
            logger.info(f"📱 Found IMEI in data: 867994064255157")
        
        # Пытаемся извлечь координаты
        if len(data) >= 20:
            # Ищем возможные координаты (4 байта big-endian)
            for i in range(len(data) - 4):
                potential_coord = struct.unpack('>i', data[i:i+4])[0]
                if -1800000000 < potential_coord < 1800000000:
                    coord = potential_coord / 10000000.0
                    if -180 <= coord <= 180:
                        logger.info(f"📍 Potential coordinate at position {i}: {coord}")
        
        return {"raw_hex": hex_data, "length": len(data)}
    
    def handle_client(self, conn, addr):
        """Обработка подключения устройства"""
        logger.info(f"🔌 New connection from {addr}")
        
        try:
            # Получаем данные
            data = conn.recv(4096)
            if not data:
                return
            
            logger.info(f"📨 Received {len(data)} bytes from {addr}")
            hex_data = binascii.hexlify(data).upper().decode()
            logger.info(f"🔧 Hex data: {hex_data}")
            
            # Определяем протокол по префиксу
            if data.startswith(b'\x00\x01'):  # Стандартный GalileoSKY
                logger.info("📋 Protocol: Standard GalileoSKY")
                response = self.create_galileosky_response()
                
            elif data.startswith(b'\x01'):  # Ваш формат
                logger.info("📋 Protocol: Custom tracker format")
                self.parse_unknown_protocol(data)
                response = self.create_generic_response()
                
            else:  # Неизвестный протокол
                logger.info("📋 Protocol: Unknown - analyzing...")
                packet_info = self.parse_unknown_protocol(data)
                response = self.create_generic_response()
            
            # Отправляем ответ
            logger.info(f"📤 Sending response: {binascii.hexlify(response).upper().decode()}")
            conn.send(response)
            logger.info("✅ Response sent successfully")
            
            # Пробуем получить еще данные
            try:
                conn.settimeout(2.0)
                while True:
                    more_data = conn.recv(4096)
                    if not more_data:
                        break
                    logger.info(f"📨 Additional data: {binascii.hexlify(more_data).upper().decode()}")
            except socket.timeout:
                pass
                
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
                
                logger.info("🚀 " + "="*60)
                logger.info(f"📍 Universal Tracker Server started!")
                logger.info(f"📍 Listening on: {self.host}:{self.port}")
                logger.info("📍 Supports: Multiple tracker protocols")
                logger.info("🚀 " + "="*60)
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
    server = UniversalTrackerServer()
    server.start()