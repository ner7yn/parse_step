from fastapi import FastAPI, Request, Response
import logging
import binascii
import uvicorn

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="GalileoSKY Proxy")

class GalileoSKYProtocol:
    """Обработчик протокола GalileoSKY"""
    
    @staticmethod
    def create_response(packet_id: int = 0) -> bytes:
        """Создает корректный ответ для устройства GalileoSKY"""
        # Базовый успешный ответ: префикс + длина + ID + флаги + CRC
        response = b'\x00\x01'  # Префикс
        response += b'\x00\x02'  # Длина пакета (2 байта)
        response += packet_id.to_bytes(2, 'big')  # ID пакета
        response += b'\x00'  # Флаги (успех)
        
        # Вычисляем CRC
        crc = GalileoSKYProtocol.calculate_crc(response)
        response += crc.to_bytes(2, 'big')
        
        return response
    
    @staticmethod
    def calculate_crc(data: bytes) -> int:
        """Вычисление CRC16 для пакета"""
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

@app.post("/")
async def receive_galileosky_data(request: Request):
    """Основной эндпоинт для устройств GalileoSKY"""
    try:
        # Получаем сырые данные
        raw_data = await request.body()
        
        logger.info(f"📨 Received {len(raw_data)} bytes from device")
        logger.info(f"🔧 Hex data: {binascii.hexlify(raw_data).decode('utf-8')}")
        
        # Пытаемся распарсить ID пакета из входящих данных
        packet_id = 0
        if len(raw_data) >= 6:
            try:
                packet_id = int.from_bytes(raw_data[4:6], 'big')
                logger.info(f"🆔 Packet ID: {packet_id}")
            except:
                pass
        
        # Логируем структуру пакета
        if len(raw_data) >= 8:
            logger.info(f"📋 Packet structure:")
            logger.info(f"   Prefix: {binascii.hexlify(raw_data[0:2]).decode()}")
            logger.info(f"   Length: {int.from_bytes(raw_data[2:4], 'big')}")
            logger.info(f"   Packet ID: {packet_id}")
            logger.info(f"   Flags: {raw_data[6]:02x}")
            if len(raw_data) > 8:
                logger.info(f"   Payload: {len(raw_data[7:-2])} bytes")
            logger.info(f"   CRC: {binascii.hexlify(raw_data[-2:]).decode()}")
        
        # Создаем корректный ответ для GalileoSKY
        response_data = GalileoSKYProtocol.create_response(packet_id)
        
        logger.info(f"📤 Sending response: {binascii.hexlify(response_data).decode('utf-8')}")
        logger.info("✅ Successfully processed GalileoSKY packet")
        
        # Возвращаем бинарный ответ
        return Response(
            content=response_data,
            media_type="application/octet-stream"
        )
        
    except Exception as e:
        logger.error(f"💥 Error processing request: {str(e)}")
        # Возвращаем ошибку в формате GalileoSKY
        error_response = b'\x00\x01\x00\x02\x00\x01\x00\x00'  # Базовый ответ с флагом ошибки
        return Response(content=error_response, media_type="application/octet-stream")

@app.get("/")
async def health_check():
    """Проверка здоровья сервера"""
    return {
        "status": "running",
        "service": "GalileoSKY Proxy", 
        "platform": "macOS",
        "endpoint": "POST /"
    }

@app.post("/galileosky")
async def alternative_endpoint(request: Request):
    """Альтернативный эндпоинт для GalileoSKY"""
    return await receive_galileosky_data(request)

if __name__ == "__main__":
    logger.info("🚀 Starting GalileoSKY Proxy Server for macOS")
    logger.info("📍 Listening on: 0.0.0.0:8000")
    logger.info("📡 Endpoint: POST http://<your_ip>:8000/")
    logger.info("🔧 Protocol: GalileoSKY binary")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )