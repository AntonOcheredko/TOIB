import hashlib


def hash_password(password):
    # Создаем объект хеша SHA-256
    sha256_hash = hashlib.sha256()
    # Преобразуем строку пароля в байты и обновляем хеш
    sha256_hash.update(password.encode('utf-8'))
    # Получаем хешированное представление в виде шестнадцатеричной строки
    hashed_password = sha256_hash.hexdigest()
    return hashed_password

password = input("Введите пароль: ")
hashed_password = hash_password(password)
print("Хеш пароля (SHA-256):", hashed_password)