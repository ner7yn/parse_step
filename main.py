import socket
import threading
import struct
import crcmod
from datetime import datetime, timedelta
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('galileosky_server.log'),
        logging.StreamHandler()
    ]
)

class GalileoskyServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}
        self.crc16_modbus = crcmod.predefined.mkCrcFun('modbus')
        
    def start(self):
        """Запуск сервера"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            logging.info(f"Galileosky сервер запущен на {self.host}:{self.port}")
            
            while True:
                client_socket, client_address = self.socket.accept()
                logging.info(f"Новое подключение: {client_address}")
                
                # Запускаем отдельный поток для каждого клиента
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            logging.error(f"Ошибка сервера: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, client_address):
        """Обработка подключения клиента"""
        buffer = b''
        client_info = {'imei': None, 'device_id': None}
        
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                buffer += data
                buffer = self.process_buffer(buffer, client_socket, client_address, client_info)
                
        except Exception as e:
            logging.error(f"Ошибка обработки клиента {client_address}: {e}")
        finally:
            client_socket.close()
            logging.info(f"Клиент отключен: {client_address}")
    
    def process_buffer(self, buffer, client_socket, client_address, client_info):
        """Обработка буфера данных"""
        while len(buffer) >= 3:  # Минимальный размер для определения пакета
            header = buffer[0]
            
            # Определяем тип пакета по заголовку
            if header == 0x01:  # Первый пакет или команда
                if len(buffer) < 3:
                    break
                    
                length_bytes = struct.unpack_from('<H', buffer, 1)[0]
                packet_length = (length_bytes & 0x7FFF) + 5  # +3 байта заголовок+длина, +2 CRC
                
                if len(buffer) < packet_length:
                    break
                    
                packet_data = buffer[:packet_length]
                buffer = buffer[packet_length:]
                
                self.process_packet(packet_data, client_socket, client_address, client_info)
                
            elif header == 0x08:  # Сжатый пакет
                if len(buffer) < 3:
                    break
                    
                length = struct.unpack_from('<H', buffer, 1)[0]
                packet_length = length + 5  # +3 байта заголовок+длина, +2 CRC
                
                if len(buffer) < packet_length:
                    break
                    
                packet_data = buffer[:packet_length]
                buffer = buffer[packet_length:]
                
                self.process_compressed_packet(packet_data, client_socket, client_address, client_info)
                
            elif header == 0x02:  # Пакет подтверждения (от сервера к терминалу)
                # Это исходящий пакет, пропускаем
                if len(buffer) >= 5:
                    buffer = buffer[5:]
                else:
                    break
            else:
                # Неизвестный заголовок, пропускаем байт
                logging.warning(f"Неизвестный заголовок: 0x{header:02x}")
                buffer = buffer[1:]
                
        return buffer
    
    def process_packet(self, data, client_socket, client_address, client_info):
        """Обработка обычного пакета"""
        try:
            parsed = self.parse_head_packet(data)
            
            # Логируем информацию о пакете
            logging.info(f"Пакет от {client_address}: "
                        f"Длина={parsed['length']}, "
                        f"CRC={'VALID' if parsed['crc_valid'] else 'INVALID'}")
            
            # Извлекаем IMEI и ID устройства
            for tag in parsed['tags']:
                if tag['tag'] == '0x03' and tag['name'] == 'IMEI':
                    client_info['imei'] = tag['value']
                    logging.info(f"IMEI устройства: {tag['value']}")
                elif tag['tag'] == '0x04' and tag['name'] == 'ID устройства':
                    client_info['device_id'] = tag['value']
            
            # Отправляем подтверждение
            ack_packet = self.create_ack_packet(data)
            client_socket.send(ack_packet)
            
            # Обрабатываем данные
            self.process_data(parsed, client_info)
            
        except Exception as e:
            logging.error(f"Ошибка обработки пакета: {e}")
    
    def process_compressed_packet(self, data, client_socket, client_address, client_info):
        """Обработка сжатого пакета"""
        try:
            parsed = self.parse_compressed_packet(data)
            
            logging.info(f"Сжатый пакет от {client_address}: "
                        f"Записей={len(parsed['records'])}")
            
            # Отправляем подтверждение
            ack_packet = self.create_ack_packet(data)
            client_socket.send(ack_packet)
            
            # Обрабатываем данные
            for record in parsed['records']:
                self.process_compressed_data(record, client_info)
                
        except Exception as e:
            logging.error(f"Ошибка обработки сжатого пакета: {e}")
    
    def parse_head_packet(self, data):
        """Разбор первого пакета (аналогично предыдущей реализации)"""
        if len(data) < 5:
            raise ValueError("Packet too short")
        
        result = {}
        index = 0
        
        header = data[index]
        index += 1
        
        length_bytes = struct.unpack_from('<H', data, index)[0]
        index += 2
        
        has_unsent_data = (length_bytes & 0x8000) != 0
        actual_length = length_bytes & 0x7FFF
        
        result['header'] = header
        result['has_unsent_data'] = has_unsent_data
        result['length'] = actual_length
        
        tags = []
        while index < (3 + actual_length - 2):
            if index >= len(data):
                break
                
            tag = data[index]
            index += 1
            
            if tag == 0x01:  # Тип терминала
                tag_data = data[index]
                index += 1
                tags.append({'tag': '0x01', 'name': 'Тип терминала', 'value': tag_data})
                
            elif tag == 0x02:  # Версия прошивки
                tag_data = data[index]
                index += 1
                tags.append({'tag': '0x02', 'name': 'Версия прошивки', 'value': tag_data})
                
            elif tag == 0x03:  # IMEI
                imei_bytes = data[index:index+15]
                imei = imei_bytes.decode('ascii', errors='ignore')
                index += 15
                tags.append({'tag': '0x03', 'name': 'IMEI', 'value': imei})
                
            elif tag == 0x04:  # ID устройства
                device_id = struct.unpack_from('<H', data, index)[0]
                index += 2
                tags.append({'tag': '0x04', 'name': 'ID устройства', 'value': device_id})
                
            elif tag == 0xFE:  # Расширенные теги
                ext_tags_length = struct.unpack_from('<H', data, index)[0]
                index += 2
                
                ext_tags = []
                ext_tags_end = index + ext_tags_length
                
                while index < ext_tags_end and index < len(data):
                    ext_tag = struct.unpack_from('<H', data, index)[0]
                    index += 2
                    
                    if ext_tag == 0x0001:
                        ext_value = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        ext_tags.append({'tag': f'0x{ext_tag:04x}', 'value': ext_value})
                    else:
                        if ext_tags_end - index >= 4:
                            index += 4
                
                tags.append({'tag': '0xFE', 'name': 'Расширенные теги', 'value': ext_tags})
                
            else:
                tags.append({'tag': f'0x{tag:02x}', 'name': 'Неизвестный тег', 'value': 'Пропущен'})
        
        result['tags'] = tags
        
        received_crc = struct.unpack_from('<H', data, 3 + actual_length)[0]
        calculated_crc = self.crc16_modbus(data[:3 + actual_length])
        result['crc_valid'] = (received_crc == calculated_crc)
        
        return result
    
    def parse_compressed_packet(self, data):
        """Разбор сжатого пакета"""
        if len(data) < 5:
            raise ValueError("Packet too short")
        
        result = {}
        index = 0
        
        header = data[index]
        index += 1
        
        length = struct.unpack_from('<H', data, index)[0]
        index += 2
        
        result['header'] = header
        result['length'] = length
        
        records = []
        
        while index < (3 + length - 2):
            record = {}
            
            if index + 10 > len(data):
                break
                
            min_data = data[index:index+10]
            index += 10
            
            coord_data = self.parse_minimal_data(min_data)
            record['minimal_data'] = coord_data
            
            records.append(record)
        
        result['records'] = records
        
        if index + 2 <= len(data):
            received_crc = struct.unpack_from('<H', data, index)[0]
            calculated_crc = self.crc16_modbus(data[:3 + length])
            result['crc_valid'] = (received_crc == calculated_crc)
        
        return result
    
    def parse_minimal_data(self, data):
        """Разбор минимального набора данных"""
        if len(data) < 10:
            return {}
        
        result = {}
        
        # Время (25 бит)
        time_bits = int.from_bytes(data[0:4], 'little') & 0x1FFFFFF
        current_year = datetime.now().year
        base_time = datetime(current_year, 1, 1)
        record_time = base_time + timedelta(seconds=time_bits)
        result['timestamp'] = record_time
        
        # Координаты
        lon_raw = ((data[3] & 0x3F) << 16) | (data[4] << 8) | data[5]
        longitude = (360 * lon_raw) / 4194304 - 180
        result['longitude'] = longitude
        
        lat_raw = ((data[6] & 0x1F) << 16) | (data[7] << 8) | data[8]
        latitude = (180 * lat_raw) / 2097152 - 90
        result['latitude'] = latitude
        
        coord_valid = (data[3] & 0x40) == 0
        result['coordinates_valid'] = coord_valid
        
        alarm = (data[8] & 0x02) != 0
        result['alarm'] = alarm
        
        user_tag = ((data[8] & 0x01) << 8) | data[9]
        result['user_tag'] = user_tag
        
        return result
    
    def create_ack_packet(self, received_packet):
        """Создание пакета подтверждения приема"""
        packet = bytearray()
        
        # Заголовок подтверждения
        packet.append(0x02)
        
        # Контрольная сумма полученного пакета
        crc_received = self.crc16_modbus(received_packet)
        packet.extend(struct.pack('<H', crc_received))
        
        return bytes(packet)
    
    def send_command(self, client_socket, imei, device_id, command_text, command_id=0):
        """Отправка команды терминалу"""
        try:
            command_packet = self.create_command_packet(imei, device_id, command_text, command_id)
            client_socket.send(command_packet)
            logging.info(f"Отправлена команда: {command_text}")
        except Exception as e:
            logging.error(f"Ошибка отправки команды: {e}")
    
    def create_command_packet(self, imei, device_id, command_text, command_id=0):
        """Создание пакета команды"""
        packet = bytearray()
        
        packet.append(0x01)
        packet.extend(b'\x00\x00')  # Временная длина
        
        packet.append(0x03)
        packet.extend(imei.encode('ascii'))
        
        packet.append(0x04)
        packet.extend(struct.pack('<H', device_id))
        
        packet.append(0xE0)
        packet.extend(struct.pack('<I', command_id))
        
        packet.append(0xE1)
        command_bytes = command_text.encode('cp1251')
        packet.append(len(command_bytes))
        packet.extend(command_bytes)
        
        length = len(packet) - 3
        packet[1:3] = struct.pack('<H', length)
        
        crc = self.crc16_modbus(packet)
        packet.extend(struct.pack('<H', crc))
        
        return bytes(packet)
    
    def process_data(self, parsed_data, client_info):
        """Обработка данных из пакета"""
        # Здесь можно сохранять данные в БД, отправлять в другие системы и т.д.
        logging.info(f"Обработка данных от IMEI: {client_info.get('imei', 'Unknown')}")
        
        for tag in parsed_data['tags']:
            logging.info(f"  Тег {tag['tag']}: {tag['value']}")
    
    def process_compressed_data(self, record, client_info):
        """Обработка данных из сжатого пакета"""
        minimal_data = record.get('minimal_data', {})
        
        if minimal_data:
            logging.info(f"Координаты: {minimal_data.get('latitude'):.6f}, "
                        f"{minimal_data.get('longitude'):.6f}, "
                        f"Время: {minimal_data.get('timestamp')}, "
                        f"Тревога: {minimal_data.get('alarm')}")
    
    def stop(self):
        """Остановка сервера"""
        if self.socket:
            self.socket.close()
            logging.info("Сервер остановлен")

def main():
    """Запуск сервера"""
    server = GalileoskyServer(host='0.0.0.0', port=8000)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logging.info("Остановка сервера по команде пользователя")
        server.stop()
    except Exception as e:
        logging.error(f"Ошибка запуска сервера: {e}")

if __name__ == "__main__":
    main()