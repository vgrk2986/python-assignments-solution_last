# 🔐 VT Scanner - VirusTotal API Scanner

Python-скрипт для проверки файлов через VirusTotal API. Разработан для Google Colab.

## 📋 Описание проекта

Скрипт обращается к API VirusTotal для получения информации о файле по его хешу (MD5, SHA-1, SHA-256). 
Выводит результаты сканирования антивирусами в удобном формате.

## ✨ Функциональность

- ✅ Авторизация через API ключ VirusTotal
- ✅ Проверка файлов по хешу (MD5, SHA-1, SHA-256)
- ✅ Валидация формата хеша перед отправкой
- ✅ Структурированный вывод результатов
- ✅ Сохранение JSON ответа в файл
- ✅ Тестовые хеши для демонстрации

## 🚀 Быстрый старт в Google Colab

### 1. Получение API ключа

1. Зарегистрируйтесь на [VirusTotal](https://www.virustotal.com)
2. Перейдите в профиль → API Key
3. Скопируйте ключ (бесплатный тариф: 4 запроса/мин)

### 2. Код для Google Colab

```python
# Скопируйте этот код в ячейку Google Colab

import requests
import json
import re
from IPython.display import HTML, FileLink

# ВАШ API КЛЮЧ (замените на свой)
API_KEY = "0fd5e5d4b54c089829f1f244b1a370bc87e2441fa4718f0be1b80cbca95b5eda"

def validate_hash(hash_string):
    '''Проверка корректности хеша'''
    hash_string = hash_string.strip().lower()
    
    if len(hash_string) == 64 and re.match(r'^[a-f0-9]+$', hash_string):
        return hash_string, "SHA-256"
    elif len(hash_string) == 40 and re.match(r'^[a-f0-9]+$', hash_string):
        return hash_string, "SHA-1"
    elif len(hash_string) == 32 and re.match(r'^[a-f0-9]+$', hash_string):
        return hash_string, "MD5"
    else:
        return None, None

def check_file_virustotal(api_key, file_hash, hash_type):
    '''Отправка запроса к VirusTotal API'''
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        print(f"\n🔄 Отправка запроса к VirusTotal API...")
        print(f"📋 Тип хеша: {hash_type}")
        print(f"📋 Хеш: {file_hash}")
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            print("✅ Запрос успешно выполнен!")
            return response.json()
        elif response.status_code == 404:
            print("❌ Файл не найден в базе VirusTotal")
            return None
        else:
            print(f"❌ Ошибка HTTP: {response.status_code}")
            print(f"Сообщение: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def display_results(data):
    '''Отображение результатов'''
    if not data:
        return
    
    print("\n" + "="*70)
    print("📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("="*70)
    
    try:
        attributes = data.get('data', {}).get('attributes', {})
        
        print(f"\n📁 Файл: {attributes.get('meaningful_name', 'Неизвестно')}")
        print(f"📏 Размер: {attributes.get('size', 0)} байт")
        print(f"📝 Тип: {attributes.get('type_description', 'Неизвестно')}")
        
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        
        print(f"\n🛡️ Статистика проверки:")
        print(f"   🔴 Вредоносных: {malicious}")
        print(f"   🟡 Подозрительных: {stats.get('suspicious', 0)}")
        print(f"   🟢 Безопасных: {stats.get('harmless', 0)}")
        print(f"   ⚪ Не обнаружено: {stats.get('undetected', 0)}")
        
        if malicious > 0:
            print(f"\n⚠️  ФАЙЛ ОПАСЕН! Обнаружен {malicious} антивирусами")
        else:
            print(f"\n✅ Файл безопасен (по данным VirusTotal)")
            
    except Exception as e:
        print(f"❌ Ошибка при обработке: {e}")

# Основная программа
print("🔐 VT Scanner - Проверка файлов через VirusTotal")
print("="*70)

print(f"\n✅ Используется API ключ: {API_KEY[:10]}...")

print("\n🔍 ВВЕДИТЕ ХЕШ ФАЙЛА:")
print("   • EICAR (SHA-256): 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
print("   • EICAR (MD5): 44d88612fea8a8f36de82e1278abb02f")
print("   • Notepad.exe: можно найти в интернете")

file_hash = input("👉 Hash: ").strip()

# Валидация хеша
valid_hash, hash_type = validate_hash(file_hash)

if not valid_hash:
    print("\n❌ Некорректный хеш! Используем тестовый EICAR...")
    valid_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    hash_type = "SHA-256"

print("\n" + "="*70)
print("🚀 ВЫПОЛНЕНИЕ ЗАПРОСА...")

# Выполняем запрос
result = check_file_virustotal(API_KEY, valid_hash, hash_type)

if result:
    display_results(result)
    
    # Сохраняем результат
    with open('virustotal_result.json', 'w') as f:
        json.dump(result, f, indent=2)
    print("\n📄 Результат сохранен в 'virustotal_result.json'")
    
    # Создаем ссылку для скачивания
    print("\n📥 Скачать результат:")
    display(FileLink('virustotal_result.json'))
else:
    print("\n❌ Не удалось получить результаты")

print("\n" + "="*70)
print("✅ Скрипт завершил работу")
3. Тестовые хеши
Тип	Хеш	Описание
SHA-256	275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f	EICAR тестовый вирус
MD5	44d88612fea8a8f36de82e1278abb02f	EICAR тестовый вирус
SHA-1	3395856ce81f2b7382dee72602f798b642f14140	EICAR тестовый вирус
📊 Пример вывода
🔐 VT Scanner - Проверка файлов через VirusTotal
======================================================================

✅ Используется API ключ: 0fd5e5d4b5...

🔍 ВВЕДИТЕ ХЕШ ФАЙЛА:
👉 Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

======================================================================
🚀 ВЫПОЛНЕНИЕ ЗАПРОСА...

🔄 Отправка запроса к VirusTotal API...
📋 Тип хеша: SHA-256
📋 Хеш: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
✅ Запрос успешно выполнен!

======================================================================
📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ
======================================================================

📁 Файл: eicar.com
📏 Размер: 68 байт
📝 Тип: Text

🛡️ Статистика проверки:
   🔴 Вредоносных: 62
   🟡 Подозрительных: 0
   🟢 Безопасных: 0
   ⚪ Не обнаружено: 8

⚠️  ФАЙЛ ОПАСЕН! Обнаружен 62 антивирусами

======================================================================
✅ Скрипт завершил работу
⚠️ Важные замечания
Бесплатный API ключ ограничен 4 запросами в минуту

При превышении лимита подождите 1 минуту

Хеш должен быть в hex формате (только символы a-f и 0-9)

Для первого сканирования файла его нужно загрузить на VirusTotal

🔧 Устранение неполадок
Проблема	Решение
Ошибка 401	Неверный API ключ
Ошибка 404	Файл не найден в базе
Ошибка 429	Слишком много запросов
Ошибка 400	Неверный формат хеша
📚 Полезные ссылки
Документация VirusTotal API

VirusTotal Web Interface

EICAR тестовый файл

<div align="center"> <sub>Разработано для учебного задания по курсу "Python для автоматизации"</sub> <br> <sub>📅 2024</sub> </div> 