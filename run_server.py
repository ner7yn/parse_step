#!/usr/bin/env python3
"""
Скрипт для запуска FastAPI сервера
"""

import uvicorn

if __name__ == "__main__":
    print("Запуск сервера GalileoSKY Protocol Handler...")
    print("Сервер будет доступен по адресу: http://localhost:8000")
    print("Эндпоинты:")
    print("  GET  / - проверка работоспособности")
    print("  POST /galileosky - прием бинарных данных")
    print("  POST /galileosky/hex - прием hex-строки")
    print()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=5555,
        reload=True,
        log_level="info"
    )