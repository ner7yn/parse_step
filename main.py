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

class CustomTrackerServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
    
    def calculate_crc8(self, data: bytes) -> int:
        """CRC8 calculation (common in trackers)"""
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = (crc << 1) ^ 0x07
                else:
                    crc <<= 1
                crc &= 0xFF
        return crc
    
    def calculate_crc16(self, data: bytes) -> int:
        """CRC16 MODBUS calculation"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc = crc >> 1
        return crc
    
    def parse_custom_protocol(self, data: bytes):
        """Парсим кастомный протокол трекера"""
        hex_data = binascii.hexlify(data).upper().decode()
        
        result = {
            "raw_hex": hex_data,
            "length": len(data),
            "imei": None,
            "coordinates": None,
            "speed": None,
            "timestamp": None
        }
        
        try:
            # Анализируем структуру пакета
            logger.info(f"🔍 Packet analysis:")
            logger.info(f"   Full: {hex_data}")
            
            # IMEI находится в позиции после 012180019D022603
            # 383637393934303634323535313537 = 867994064255157
            if b'867994064255157' in data:
                imei_pos = data.find(b'867994064255157')
                result["imei"] = "867994064255157"
                logger.info(f"📱 IMEI: {result['imei']} at position {imei_pos}")
            
            # Пытаемся найти координаты (4 байта после 0432)
            if b'\x04\x32' in data:
                pos = data.find(b'\x04\x32') + 2
                if pos + 8 <= len(data):
                    # Координаты могут быть в следующих 8 байтах
                    lat_bytes = data[pos:pos+4]
                    lon_bytes = data[pos+4:pos+8]
                    
                    try:
                        # Пробуем разные форматы координат
                        lat = struct.unpack('>i', lat_bytes)[0] / 1000000.0
                        lon = struct.unpack('>i', lon_bytes)[0] / 1000000.0
                        
                        if -90 <= lat <= 90 and -180 <= lon <= 180:
                            result["coordinates"] = (lat, lon)
                            logger.info(f"📍 Coordinates: {lat}, {lon}")
                    except:
                        pass
            
            # Последний байт - вероятно CRC
            if len(data) > 0:
                received_crc = data[-1]
                calculated_crc = self.calculate_crc8(data[:-1])
                result["crc_valid"] = (received_crc == calculated_crc)
                logger.info(f"🔢 CRC: received={received_crc:02X}, calculated={calculated_crc:02X}, valid={result['crc_valid']}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Parse error: {e}")
            return result
    
    def create_proper_response(self, data: bytes) -> bytes:
        """Создает правильный ответ на основе входящих данных"""
        # Анализируем что прислали
        hex_data = binascii.hexlify(data).upper().decode()
        
        # Если это пакет начинающийся с 0121, отвечаем в том же стиле
        if data.startswith(b'\x01\x21'):
            # Создаем ответ похожий на ожидаемый устройством
            response = b'\x01\x02\x00\x01'  # Базовый ответ
            
            # Добавляем CRC
            crc = self.calculate_crc8(response)
            response += crc.to_bytes(1, 'big')
            
            logger.info(f"📤 Response type 1: {binascii.hexlify(response).upper().decode()}")
            return response
        
        # Если это пакет начинающийся с 41A4 (из логов GalileoSKY)
        elif data.startswith(b'\x41\xA4'):
            # Ответ для GalileoSKY протокола
            response = b'\x00\x01\x00\x02\x00\x00\x00'
            crc = self.calculate_crc16(response)
            response += crc.to_bytes(2, 'little')
            
            logger.info(f"📤 Response type 2 (GalileoSKY): {binascii.hexlify(response).upper().decode()}")
            return response
        
        else:
            # Универсальный ответ
            response = b'\x01\x00\x01'  # Простой подтверждающий пакет
            logger.info(f"📤 Response type 3 (generic): {binascii.hexlify(response).upper().decode()}")
            return response
    
    def handle_client(self, conn, addr):
        """Обработка подключения устройства"""
        logger.info(f"🔌 New connection from {addr}")
        
        try:
            data = conn.recv(4096)
            if not data:
                return
            
            logger.info(f"📨 Received {len(data)} bytes")
            logger.info(f"🔧 Hex: {binascii.hexlify(data).upper().decode()}")
            
            # Анализируем пакет
            packet_info = self.parse_custom_protocol(data)
            
            # Создаем правильный ответ
            response = self.create_proper_response(data)
            
            # Отправляем ответ
            conn.send(response)
            logger.info(f"✅ Response sent: {binascii.hexlify(response).upper().decode()}")
            
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
                
                logger.info("🚀 " + "="*50)
                logger.info(f"📍 Custom Tracker Server started!")
                logger.info(f"📍 Listening on: {self.host}:{self.port}")
                logger.info("🚀 " + "="*50)
                
                while True:
                    conn, addr = s.accept()
                    thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    thread.daemon = True
                    thread.start()
                    
        except Exception as e:
            logger.error(f"❌ Server error: {e}")

if __name__ == "__main__":
    server = CustomTrackerServer()
    server.start()