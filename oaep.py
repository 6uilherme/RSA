from hashlib import sha3_256
import math
import os
import hashlib
import rsa


def mgf1(seed, mask_len):
    # inicialização de variáveis
    h_len = sha3_256().digest_size # hLen: octetos de saida
    t = b"" # string vazia de octetos
    k = math.ceil(mask_len/h_len)

    # calcula valores intermediários
    for i in range(k):
        # converte o contador em 4 bytes (octeto)
        c = int.to_bytes(i, 4, "big")
        # concatena o hash da semente e do contador
        t += sha3_256(seed + c).digest()

    return t[:mask_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def oaep_encode(message, label=b'', hash_func=hashlib.sha3_256):
   h_len = hash_func().digest_size
   k = 2048
   max_message_len = k // 8 - 2 * h_len - 2
   if len(message) > max_message_len:
        raise ValueError("Mensagem muito longa para o tamanho da chave")
   # gerar um padding PS de zeros
   ps = b'\x00' * (max_message_len - len(message))
   # concatenar o hash do label, o padding PS, um byte 0x01 e a mensagem
   l_hash = hash_func(label).digest()
   db = l_hash + ps + b'\x01' + message
   # gerar uma seed aleatória
   seed = os.urandom(h_len)
   # aplicar a função MGF1 à seed para gerar dbMask
   db_mask = mgf1(seed, len(db))
   # XOR entre db e dbMask para gerar maskedDB
   masked_db = xor_bytes(db, db_mask)
   # aplicar a função MGF1 ao maskedDB para gerar seedMask
   seed_mask = mgf1(masked_db, h_len)
   # XOR entre a seed e seedMask para gerar maskedSeed
   masked_seed = xor_bytes(seed, seed_mask)
   # concatenar o maskedSeed e o maskedDB para formar o EM (Encoded Message)
   em = b'\x00' + masked_seed + masked_db
   return em

def oaep_decode(em, label=b'', hash_func=hashlib.sha3_256):
   k = 2048
   h_len = hash_func().digest_size
   if len(em) != k // 8:
        raise ValueError("Tamanho do EM inválido")
   # separar o maskedSeed e o maskedDB
   masked_seed = em[1:1 + h_len]
   masked_db = em[1 + h_len:]
   # aplicar a função MGF1 ao maskedDB para gerar seedMask
   seed_mask = mgf1(masked_db, h_len)
   # XOR entre o maskedSeed e seedMask para recuperar a seed
   seed = xor_bytes(masked_seed, seed_mask)
   # aplicar a função MGF1 à seed para gerar dbMask
   db_mask = mgf1(seed, len(masked_db))
   # XOR entre o maskedDB e dbMask para recuperar o DB
   db = xor_bytes(masked_db, db_mask)
   # separar o lHash, o padding PS, o byte 0x01 e a mensagem
   l_hash = db[:h_len]
   ps_index = db[h_len:].find(b'\x01')
   if ps_index == -1:
        raise ValueError("Decodificação falhou: byte 0x01 não encontrado")
   ps = db[h_len:h_len + ps_index]
   message = db[h_len + ps_index + 1:]
   # verificar se o lHash está correto
   if l_hash != hash_func(label).digest():
        raise ValueError("Decodificação falhou: lHash incorreto")
   return message

def main_oaep():
    message = b"Hello, OAEP with SHA-3!"
    label = b"OAEP Example"
    k = 2048  # Tamanho da chave em bits# Codificação
    em = oaep_encode(message, label)
    print(f"Encoded Message (EM): {em.hex()}")  # Decodificação
    decoded_message = oaep_decode(em, label)
    print(f"Decoded Message: {decoded_message.decode()}")

    # Parâmetros e mensagem
    message = b'Mensagem muito importante'
    seed = os.urandom(32)  # Seed aleatório (32 bytes)
    seed2 = seed

    # Codificação

    #OAEP Encode (pré-cifragem)
    encoded_message = oaep_encode(message, seed, hashlib.sha3_256)
    print("Mensagem codificada com OAEP:", encoded_message)

    num_bytes = len(encoded_message)

    msg = int.from_bytes(encoded_message, byteorder="big", signed=False)
    n, d, e = rsa.gera_chaves()
    print("n1 =",n)
    ciphertext = rsa.cifracao_rsa(msg, e, n)
    print("Mensagem cifrada com RSA:", ciphertext)

    ciphertextb64 = rsa.string_base64(ciphertext, d, n, num_bytes, seed)
    print("Mensagem + chave em base64:", ciphertextb64)

    # Decodificacao

    ciphertext, d, n, num_bytes, num_bytes_size, seed = rsa.base64_string(ciphertextb64)
    print("Mensagem para RSA:", ciphertext)
    print("Chave d = ", d)
    print("Chave n = ", n)

    decoded_ciphertext = rsa.decifracao_rsa(ciphertext, d, n)
    decoded_ciphertext = decoded_ciphertext.to_bytes(num_bytes, byteorder="big", signed=False)
    print("Mensagem decodificada do RSA:", decoded_ciphertext)

    # OAEP Decode (pós-decifragem)
    decoded_message = oaep_decode(encoded_message, seed2, hashlib.sha3_256)
    print("Mensagem original recuperada:", decoded_message)
    return decoded_message == message

