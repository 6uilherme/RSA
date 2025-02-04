import hashlib, os
from rsa import gera_chaves, cifracao_rsa, decifracao_rsa, string_base64, base64_string
from oaep import oaep_encode, oaep_decode

def assina_string(n, d, e, mensagem,  seed=1024):
    # geração de semente para OAEP
    k = 2048 # tamanho da semente do oaep
    seed = os.urandom(seed)
    # converte para formato em bytes
    mensagem_bytes = mensagem.encode()

    # gera assinatura da mensagem
    assinatura_hex = hashlib.sha3_256(mensagem.encode('utf-8')).hexdigest()
    assinatura_str_int = str(int(assinatura_hex, 16))
    assinatura = assinatura_str_int.encode()

    # OAEP Encode (pré decifragem)
    asssinatura_oaep = oaep_encode(assinatura, seed, hashlib.sha3_256)

    # encripta com o RSA
    assinatura_oaep_int = int.from_bytes(asssinatura_oaep, byteorder="big", signed=False)
    ciphertext = cifracao_rsa(assinatura_oaep_int, d, n)

    # codifica em base64
    num_bytes = len(asssinatura_oaep)
    mensagem_assinada_base64 = string_base64(ciphertext, e, n, num_bytes, seed)

    return mensagem_assinada_base64, assinatura_hex

def assina_arquivo(n, d , e, path = "mensagem.txt", seed=1024):
    # geração de semente para OAEP
    k = 2048 # tamanho da semente do oaep
    seed = os.urandom(seed)

    # Abre o arquivo e lê o conteúdo
    try:
        with open(path, 'r', encoding='utf-8') as arquivo:
            mensagem = arquivo.read()  # Lê o conteúdo do arquivo como uma string
    except FileNotFoundError:
        print(f"Erro: O arquivo '{path}' não foi encontrado.")
    except UnicodeDecodeError:
        print(f"Erro: Não foi possível decodificar o arquivo '{path}' com a codificação UTF-8.")
    except Exception as e:
        print(f"Erro ao ler o arquivo '{path}': {e}")

    # converte para formato em bytes
    mensagem_bytes = mensagem.encode()

    # gera assinatura da mensagem
    assinatura_hex = hashlib.sha3_256(mensagem.encode('utf-8')).hexdigest()
    assinatura_str_int = str(int(assinatura_hex, 16))
    assinatura = assinatura_str_int.encode()

    # OAEP Encode (pré decifragem)
    asssinatura_oaep = oaep_encode(assinatura, seed, hashlib.sha3_256)

    # encripta com o RSA
    assinatura_oaep_int = int.from_bytes(asssinatura_oaep, byteorder="big", signed=False)
    ciphertext = cifracao_rsa(assinatura_oaep_int, d, n)

    # codifica em base64
    num_bytes = len(asssinatura_oaep)
    mensagem_assinada_base64 = string_base64(ciphertext, e, n, num_bytes, seed)

    try:
        with open('mensagem_assinada_base64.txt', 'w', encoding='utf-8') as arquivo:
            arquivo.write(mensagem_assinada_base64)  # Escreve a string no arquivo
    except IOError as e:
        print(f"Erro ao escrever no arquivo 'mensagem_assinada_base64.txt': {e}")
    except Exception as e:
        print(f"Erro inesperado ao escrever no arquivo 'mensagem_assinada_base64.txt': {e}")
    try:
        with open('assinatura_hex.txt', 'w', encoding='utf-8') as arquivo:
            arquivo.write(assinatura_hex)  # Escreve a string no arquivo
    except IOError as e:
        print(f"Erro ao escrever no arquivo 'assinatura_hex.txt': {e}")
    except Exception as e:
        print(f"Erro inesperado ao escrever no arquivo 'assinatura_hex.txt': {e}")

    return mensagem_assinada_base64, assinatura_hex


def verifica_assinatura_string(mensagem_assinada, assinatura):
    # decodifica os parametros da base64
    ciphertext, e, n, num_bytes, num_bytes_seed, seed = base64_string(mensagem_assinada)

    # decodifica a semente em bytes
    seed = seed.to_bytes(num_bytes_seed, byteorder="big", signed=False)

    # desencripta com o RSA
    assinatura_oaep_int = decifracao_rsa(ciphertext, e, n)
    asssinatura_oaep = assinatura_oaep_int.to_bytes(num_bytes, byteorder="big", signed=False)

    # OAEP Decode (pós-decifragem)
    assinatura_dec = oaep_decode(asssinatura_oaep, seed, hashlib.sha3_256).decode('utf-8')
    assinatura_valida = True
    if int(assinatura, 16) == int(assinatura_dec):
        return assinatura_valida
    else:
        return not assinatura_valida

def verifica_assinatura_arquivo(mensagem_assinada = "mensagem_assinada_base64.txt", assinatura= "assinatura_hex.txt"):
    # Abre os arquivos e lê os conteúdos
    try:
        with open(mensagem_assinada, 'r', encoding='utf-8') as arquivo:
            mensagem_assinada = arquivo.read()  # lê o conteúdo do arquivo como uma string
    except FileNotFoundError:
        print(f"Erro: O arquivo '{mensagem_assinada}' não foi encontrado.")
    except UnicodeDecodeError:
        print(f"Erro: Não foi possível decodificar o arquivo '{mensagem_assinada}' com a codificação UTF-8.")
    except Exception as e:
        print(f"Erro ao ler o arquivo '{mensagem_assinada}': {e}")

    try:
        with open(assinatura, 'r', encoding='utf-8') as arquivo:
            assinatura = arquivo.read()  # Lê o conteúdo do arquivo como uma string
    except FileNotFoundError:
        print(f"Erro: O arquivo '{assinatura}' não foi encontrado.")
    except UnicodeDecodeError:
        print(f"Erro: Não foi possível decodificar o arquivo '{assinatura}' com a codificação UTF-8.")
    except Exception as e:
        print(f"Erro ao ler o arquivo '{assinatura}': {e}")

    # Decodifica os parâmetros da base64
    ciphertext, e, n, num_bytes, num_bytes_seed, seed = base64_string(mensagem_assinada)

    # Decodifica a semente em bytes
    seed = seed.to_bytes(num_bytes_seed, byteorder="big", signed=False)

    # Desencripta com o RSA
    assinatura_oaep_int = decifracao_rsa(ciphertext, e, n)
    asssinatura_oaep = assinatura_oaep_int.to_bytes(num_bytes, byteorder="big", signed=False)

    # OAEP Decode (pós-decifragem)
    assinatura_dec = oaep_decode(asssinatura_oaep, seed, hashlib.sha3_256).decode('utf-8')
    # Compara a assinatura
    assinatura_valida = True
    if int(assinatura, 16) == int(assinatura_dec):
        return assinatura_valida
    else:
        return not assinatura_valida

def main_assinatura():
    mensagem = "serei assinada"
    n_seed = 1024
    # geração de chaves
    n, d, e = gera_chaves()

    # assinatura de string
    mensagem_assinada, assinatura = assina_string(n, d, e, mensagem, n_seed)
    print("mensagem assinada:")
    print(mensagem_assinada)
    print("assinatura: ")
    print(assinatura)
    print("verificação: ")
    assinatura_valida = True
    if verifica_assinatura_string(mensagem_assinada, assinatura):
        print("assinado")
    else:
        print("erro na assinatura")
        return not assinatura_valida

    # assinatura de arquivo
    mensagem_assinada, assinatura = assina_arquivo(n, d, e, "mensagem.txt", n_seed)
    print("mensagem assinada:")
    print(mensagem_assinada)
    print("assinatura: ")
    print(assinatura)
    print("verificação: ")
    assinatura_valida = True
    if verifica_assinatura_arquivo():
        print(assinatura_valida)
        return assinatura_valida
    else:
        print("erro na assinatura")
        return not assinatura_valida