import socket
import threading
import struct
import crcmod
from datetime import datetime, timedelta
import logging
import json

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
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
        while len(buffer) >= 3:
            header = buffer[0]
            
            if header == 0x01:  # Первый пакет или команда
                if len(buffer) < 3:
                    break
                    
                length_bytes = struct.unpack_from('<H', buffer, 1)[0]
                packet_length = (length_bytes & 0x7FFF) + 5
                
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
            
            # Затем разбираем пакет
            parsed = self.parse_head_packet(data)
            
            logging.info(f"Пакет от {client_address}: Длина={parsed['length']}, CRC={'VALID' if parsed['crc_valid'] else 'INVALID'}")
            
            # Извлекаем IMEI и ID устройства
            for tag in parsed['tags']:
                if tag['tag'] == '0x03' and tag['name'] == 'IMEI':
                    client_info['imei'] = tag['value']
                elif tag['tag'] == '0x04' and tag['name'] == 'ID устройства':
                    client_info['device_id'] = tag['value']
            
            # Обрабатываем данные и выводим JSON
            json_data = self.process_data(parsed, client_info)
            logging.info(f"="*50)
            logging.info(f"JSON ДАННЫЕ:")
            logging.info(json.dumps(json_data, ensure_ascii=False, indent=2))
            logging.info(f"="*50 + "\n")
            
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
        expected_end = 3 + actual_length - 2
        
        while index < expected_end and index < len(data):
            if index >= len(data):
                break
                
            tag = data[index]
            index += 1
            
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
                        
                elif tag == 0x20:  # Дата и время (4 байта)
                    if index + 3 < len(data):
                        timestamp = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        dt = datetime(1970, 1, 1) + timedelta(seconds=timestamp)
                        # Форматируем время в читаемый вид
                        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                        tags.append({
                            'tag': '0x20', 
                            'name': 'Дата и время', 
                            'value': formatted_time,
                            'timestamp': timestamp,  # Сохраняем также timestamp
                            'datetime_iso': dt.isoformat()  # И ISO формат
                        })
                    else:
                        break

                elif tag == 0x30:  # Координаты (9 байт)
                    if index + 8 < len(data):
                        # Первый байт: количество спутников и валидность
                        flags = data[index]
                        index += 1
                        
                        satellites = flags & 0x0F
                        coord_valid = (flags >> 4) & 0x0F
                        
                        # Широта (4 байта)
                        lat_raw = struct.unpack_from('<i', data, index)[0]
                        index += 4
                        lat = lat_raw / 1000000.0
                        
                        # Долгота (4 байта)
                        lon_raw = struct.unpack_from('<i', data, index)[0]
                        index += 4
                        lon = lon_raw / 1000000.0
                        
                        tags.append({
                            'tag': '0x30', 
                            'name': 'Координаты', 
                            'value': {
                                'lat': lat,
                                'lon': lon,
                                'satellites': satellites,
                                'valid': coord_valid == 0 or coord_valid == 2
                            }
                        })
                    else:
                        break


                elif tag == 0xC0:  # Общий расход топлива (4 байта)
                    if index + 3 < len(data):
                        fuel_total = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        fuel_total_liters = fuel_total / 2.0  # литры
                        tags.append({
                            'tag': '0xC0', 
                            'name': 'Общий расход топлива', 
                            'value': fuel_total_liters
                        })
                    else:
                        break

                

                elif tag == 0xDC:  # Уровень топлива в литрах (4 байта)
                    if index + 3 < len(data):
                        fuel_liters = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        fuel_liters_value = fuel_liters / 10.0  # литры
                        tags.append({
                            'tag': '0xDC', 
                            'name': 'Уровень топлива в литрах', 
                            'value': fuel_liters_value
                        })
                    else:
                        break

                elif tag == 0xE2:  # Данные пользователя 0 (4 байта)
                    if index + 3 < len(data):
                        user_data = struct.unpack_from('<I', data, index)[0]
                        index += 4
                        tags.append({'tag': '0xE2', 'name': 'Данные пользователя 0', 'value': user_data})
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
            calculated_crc = self.crc16_modbus(data[:3 + actual_length])
            result['crc_valid'] = (received_crc == calculated_crc)
            result['received_crc'] = received_crc
            result['calculated_crc'] = calculated_crc
        else:
            result['crc_valid'] = False
        
        return result
    
    def create_ack_packet(self, received_packet):
        """Создание пакета подтверждения приема"""
        packet = bytearray()
        
        # Заголовок подтверждения
        packet.append(0x02)
        
        # Контрольная сумма полученного пакета
        if len(received_packet) >= 5:
            received_crc = struct.unpack_from('<H', received_packet, len(received_packet) - 2)[0]
        else:
            received_crc = 0
            
        packet.extend(struct.pack('<H', received_crc))
        
        return bytes(packet)
    
    def process_data(self, parsed_data, client_info):
        """Обработка данных из пакета и формирование JSON для транзакции"""
        json_data = {
            'imei': client_info.get('imei', 'Unknown'),
            'device_id': client_info.get('device_id'),
            'transaction': {} # Изменим структуру на 'transaction'
        }

        # Извлекаем нужные данные из тегов
        for tag in parsed_data['tags']:
            tag_value = tag['value']

            if tag['tag'] == '0x30':  # Координаты
                if isinstance(tag_value, dict):
                    json_data['transaction']['lat'] = tag_value.get('lat')
                    json_data['transaction']['lon'] = tag_value.get('lon')
                    json_data['transaction']['coordinates_valid'] = tag_value.get('valid')

            # elif tag['tag'] == '0xDC':  # Уровень топлива в литрах
            #     json_data['transaction']['fuel_level_l'] = tag_value

            elif tag['tag'] == '0x20':  # Время
                json_data['transaction']['time'] = tag_value

            elif tag['tag'] == '0xE2':  # Пользовательский тег 0 (ID ключа)
                # Сохраняем ID пользователя
                json_data['transaction']['card_number'] = tag_value

            elif tag['tag'] == '0xE3':  # Пользовательский тег 1 (объём/счётчик)
                # Сохраняем объём топлива (предполагаем, что это литры)
                json_data['transaction']['fuel_volume_l'] = tag_value / 400
                
        logging.info(f"Обработка данных от IMEI: {json_data['imei']}")
        
        return json_data
    
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