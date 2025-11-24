import socket
import threading
import struct
import crcmod
from datetime import datetime, timedelta
import logging
import binascii

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
                    
                logging.info(f"Получены сырые данные: {binascii.hexlify(data).upper().decode()}")
                buffer += data
                buffer = self.process_buffer(buffer, client_socket, client_address, client_info)
                
        except Exception as e:
            logging.error(f"Ошибка обработки клиента {client_address}: {e}")
        finally:
            client_socket.close()
            logging.info(f"Клиент отключен: {client_address}")
    
    def process_buffer(self, buffer, client_socket, client_address, client_info):
        """Обработка буфера данных"""
        while len(buffer) >= 3:
            header = buffer[0]
            
            if header == 0x01:  # Первый пакет или команда
                if len(buffer) < 3:
                    break
                    
                length_bytes = struct.unpack_from('<H', buffer, 1)[0]
                packet_length = (length_bytes & 0x7FFF) + 5  # +3 байта заголовок+длина, +2 CRC
                
                logging.info(f"Ожидаемая длина пакета: {packet_length} байт, в буфере: {len(buffer)} байт")
                
                if len(buffer) < packet_length:
                    break
                    
                packet_data = buffer[:packet_length]
                buffer = buffer[packet_length:]
                
                self.process_packet(packet_data, client_socket, client_address, client_info)
                
            elif header == 0x08:  # Сжатый пакет
                if len(buffer) < 3:
                    break
                    
                length = struct.unpack_from('<H', buffer, 1)[0]
                packet_length = length + 5
                
                if len(buffer) < packet_length:
                    break
                    
                packet_data = buffer[:packet_length]
                buffer = buffer[packet_length:]
                
                self.process_compressed_packet(packet_data, client_socket, client_address, client_info)
                
            else:
                logging.warning(f"Неизвестный заголовок: 0x{header:02x}")
                buffer = buffer[1:]
                
        return buffer
    
    def process_packet(self, data, client_socket, client_address, client_info):
        """Обработка обычного пакета"""
        try:
            # СРАЗУ отправляем подтверждение
            ack_packet = self.create_ack_packet(data)
            client_socket.send(ack_packet)
            logging.info(f"Отправлено подтверждение: {binascii.hexlify(ack_packet).upper().decode()}")
            
            # Затем разбираем пакет
            parsed = self.parse_head_packet(data)
            
            logging.info(f"Пакет от {client_address}: Длина={parsed['length']}, CRC={'VALID' if parsed['crc_valid'] else 'INVALID'}")
            
            # Извлекаем IMEI и ID устройства
            for tag in parsed['tags']:
                if tag['tag'] == '0x03' and tag['name'] == 'IMEI':
                    client_info['imei'] = tag['value']
                    logging.info(f"IMEI устройства: {tag['value']}")
                elif tag['tag'] == '0x04' and tag['name'] == 'ID устройства':
                    client_info['device_id'] = tag['value']
            
            # Обрабатываем данные
            self.process_data(parsed, client_info)
            
        except Exception as e:
            logging.error(f"Ошибка обработки пакета: {e}")
    
    def parse_head_packet(self, data):
        """Разбор первого пакета"""
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
        expected_end = 3 + actual_length - 2  # -2 для CRC
        
        logging.info(f"Разбор пакета: длина={actual_length}, позиция={index}, ожидаемый конец={expected_end}")
        
        while index < expected_end and index < len(data):
            if index >= len(data):
                break
                
            tag = data[index]
            index += 1
            
            logging.info(f"Обработка тега 0x{tag:02x} на позиции {index-1}")
            
            try:
                if tag == 0x01:  # Тип терминала (1 байт)
                    if index < len(data):
                        tag_data = data[index]
                        index += 1
                        tags.append({'tag': '0x01', 'name': 'Тип терминала', 'value': tag_data})
                    else:
                        break
                        
                elif tag == 0x02:  # Версия прошивки (1 байт)
                    if index < len(data):
                        tag_data = data[index]
                        index += 1
                        tags.append({'tag': '0x02', 'name': 'Версия прошивки', 'value': tag_data})
                    else:
                        break
                        
                elif tag == 0x03:  # IMEI (15 байт)
                    if index + 14 < len(data):
                        imei_bytes = data[index:index+15]
                        imei = imei_bytes.decode('ascii', errors='ignore')
                        index += 15
                        tags.append({'tag': '0x03', 'name': 'IMEI', 'value': imei})
                    else:
                        break
                        
                elif tag == 0x04:  # ID устройства (2 байта)
                    if index + 1 < len(data):
                        device_id = struct.unpack_from('<H', data, index)[0]
                        index += 2
                        tags.append({'tag': '0x04', 'name': 'ID устройства', 'value': device_id})
                    else:
                        break
                        
                elif tag == 0xE2:  # Данные пользователя 0 (4 байта)
                    if index + 3 < len(data):
                        user_data = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        tags.append({'tag': '0xE2', 'name': 'Данные пользователя 0', 'value': user_data})
                    else:
                        break
                        
                elif tag == 0xA0:  # CAN8BITR15 (1 байт)
                    if index < len(data):
                        can_data = data[index]
                        index += 1
                        tags.append({'tag': '0xA0', 'name': 'CAN8BITR15', 'value': can_data})
                    else:
                        break
                        
                elif tag == 0x97:  # Неизвестный тег (1 байт)
                    if index < len(data):
                        tag_data = data[index]
                        index += 1
                        tags.append({'tag': '0x97', 'name': 'Неизвестный тег 0x97', 'value': tag_data})
                    else:
                        break
                        
                elif tag == 0xA7:  # Неизвестный тег (1 байт)
                    if index < len(data):
                        tag_data = data[index]
                        index += 1
                        tags.append({'tag': '0xA7', 'name': 'Неизвестный тег 0xA7', 'value': tag_data})
                    else:
                        break
                        
                elif tag == 0xE3:  # Данные пользователя 1 (4 байта)
                    if index + 3 < len(data):
                        user_data = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        tags.append({'tag': '0xE3', 'name': 'Данные пользователя 1', 'value': user_data})
                    else:
                        break
                        
                elif tag == 0xFE:  # Расширенные теги
                    if index + 1 < len(data):
                        ext_tags_length = struct.unpack_from('<H', data, index)[0]
                        index += 2
                        
                        ext_tags = []
                        ext_tags_end = index + ext_tags_length
                        
                        while index < ext_tags_end and index < len(data):
                            if index + 1 < len(data):
                                ext_tag = struct.unpack_from('<H', data, index)[0]
                                index += 2
                                
                                if ext_tags_end - index >= 4:
                                    ext_value = struct.unpack_from('<I', data, index)[0]
                                    index += 4
                                    ext_tags.append({'tag': f'0x{ext_tag:04x}', 'value': ext_value})
                                else:
                                    break
                            else:
                                break
                        
                        tags.append({'tag': '0xFE', 'name': 'Расширенные теги', 'value': ext_tags})
                    else:
                        break
                        
                else:
                    # Для неизвестных тегов пропускаем 1 байт по умолчанию
                    if index < len(data):
                        tag_data = data[index]
                        index += 1
                        tags.append({'tag': f'0x{tag:02x}', 'name': 'Неизвестный тег', 'value': tag_data})
                    else:
                        break
                        
            except Exception as e:
                logging.error(f"Ошибка разбора тега 0x{tag:02x}: {e}")
                break
        
        result['tags'] = tags
        
        # Проверка контрольной суммы
        if 3 + actual_length + 2 <= len(data):
            received_crc = struct.unpack_from('<H', data, 3 + actual_length)[0]
            # CRC рассчитывается для данных БЕЗ CRC поля
            calculated_crc = self.crc16_modbus(data[:3 + actual_length])
            result['crc_valid'] = (received_crc == calculated_crc)
            result['received_crc'] = received_crc
            result['calculated_crc'] = calculated_crc
            
            logging.info(f"CRC проверка: получено=0x{received_crc:04X}, вычислено=0x{calculated_crc:04X}, valid={result['crc_valid']}")
        else:
            result['crc_valid'] = False
            logging.warning("Недостаточно данных для проверки CRC")
        
        return result
    
    def create_ack_packet(self, received_packet):
        """
        Создание пакета подтверждения приема
        ВАЖНО: В поле контрольной суммы отправляется CRC полученного пакета
        """
        packet = bytearray()
        
        # Заголовок подтверждения
        packet.append(0x02)
        
        # Контрольная сумма полученного пакета (берется ИЗ полученного пакета)
        if len(received_packet) >= 5:
            # Получаем CRC из полученного пакета (последние 2 байта)
            received_crc = struct.unpack_from('<H', received_packet, len(received_packet) - 2)[0]
        else:
            received_crc = 0
            
        packet.extend(struct.pack('<H', received_crc))
        
        logging.info(f"ACK пакет: заголовок=0x02, CRC=0x{received_crc:04X}")
        return bytes(packet)
    
    def process_data(self, parsed_data, client_info):
        """Обработка данных из пакета"""
        logging.info(f"Обработка данных от IMEI: {client_info.get('imei', 'Unknown')}")
        
        for tag in parsed_data['tags']:
            logging.info(f"  Тег {tag['tag']} ({tag['name']}): {tag['value']}")
    
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