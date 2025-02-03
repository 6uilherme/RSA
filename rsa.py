from random import randint
from random import getrandbits
from base64 import b64encode, b64decode

# escreve n-1 = 2**k*q
def doiskq(n):
  k = 0
  q = n-1
  while q % 2 == 0:
    q //= 2
    k += 1
  return k,q

# verifica se n e um numero de composto (carmichael)
def composto(n, a):
  k,q = doiskq(n) # escreve n-1 = 2**k*q

  # se a**q mod n = 1, então retorna False (inconclusivo)
  r = pow(a, q, n) # calcula a**q mod (n) de forma eficiente
  if r == 1:
      return False

  # se a**(2**j*q) mod n = n - 1, então retorna False (inconclusivo)
  for j in range(k):
      if r == n-1:
          return False
      r = r**2 % n

  # caso contrário devolva True (composto)
  return True

# verifica, em t vezes, se n e composto ou provavelmente primo
def miller_rabin(n, t):
  for i in range(t):
      # escolha aleatoria de 1 < a < n-1
      a = randint(2, n-1)
      if composto(n, a):
          return True
  return False

def primo(bits=1024, t=10):
  n = getrandbits(bits)
  while miller_rabin(n,t):
    n = getrandbits(bits)
  return n

def fi_euler(p,q):
  return (p-1)*(q-1)

def chave_publica(bits=1024, t=10, e=None):
  if e is None:
      e = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
  p = primo(bits,t)
  q = primo(bits,t)
  fi_n = fi_euler(p,q)
  for i in e:
    if fi_n % e[i] != 0:
      return e[i], p*q, fi_n
  raise ValueError("valores inválidos para e")

# para encontrar o valor da chave privada d (e*d - fi(n)*q = 1)
def algoritmo_euclideano_estendido(e, fi_n):
  if fi_n == 0:
      return 1, 0
  else:
      x1, y1 = algoritmo_euclideano_estendido(fi_n, e % fi_n)
      x = y1
      y = x1 - (e // fi_n) * y1
      return x, y

# retorna uma chave d>0
def chave_d(e, fi_n):
  d, q = algoritmo_euclideano_estendido(e, fi_n)
  # Ajusta d para ser maior que zero
  d = d % fi_n
  if d < 0:
    d += fi_n
  return d

def gera_chaves(bits=1024, t=10):
  e, n, fi = chave_publica(bits,t)
  d = chave_d(e, fi)
  n_hex = hex(n)
  d_hex = hex(d)
  e_hex = hex(e)
  try:
      with open('chaves.txt', 'w', encoding='utf-8') as arquivo:
          arquivo.write("chave n:\n")
          arquivo.write(n_hex)
          arquivo.write("\nchave d:\n")
          arquivo.write(d_hex)
          arquivo.write("\nchave e:\n")
          arquivo.write(e_hex)
  except IOError as e:
      print(f"Erro ao escrever no arquivo 'chaves.txt': {e}")
  except Exception as e:
      print(f"Erro inesperado ao escrever no arquivo 'chaves.txt': {e}")

  return n_hex, d_hex, e_hex

def cifracao_rsa(m, e_hex, n_hex):
    n = int(n_hex,16)
    e = int(e_hex, 16)
    return pow(m, e, n)

def decifracao_rsa(c, d_hex, n_hex):
    n = int(n_hex,16)
    d = int(d_hex,16)
    return pow(c, d, n)

def string_base64(input_string: str, d_hex, n_hex, num_bytes, seed):
    # codifica seed para inteiro
    num_bytes_seed = len(seed)
    seed = int.from_bytes(seed, byteorder="big", signed=False)
    d = int(d_hex, 16)
    n = int(n_hex, 16)
    # cria bloco para base64
    bloco = str(input_string) + "*" + str(d) + "*" + str(n) + "*" + str(num_bytes) + "*" + str(num_bytes_seed) + "*" + str(seed)
    # Converte o bloco para bytes
    byte_data = bloco.encode('utf-8')
    # Converte os bytes para base64
    encoded_data = b64encode(byte_data)
    # Retorna como uma string
    return encoded_data.decode('utf-8')

def base64_string(encoded_string):
    # decodifica a base64
    bloco = b64decode(encoded_string).decode('utf-8')

    # divide o bloco
    output_string = ""
    for i in range(len(bloco)):
        if bloco[i] == "*":
            bloco = bloco[i+1:]
            break
        output_string += bloco[i]
    e = ""
    for i in range(len(bloco)):
        if bloco[i] == "*":
            bloco = bloco[i+1:]
            break
        e += bloco[i]
    n = ""
    for i in range(len(bloco)):
        if bloco[i] == "*":
            bloco = bloco[i+1:]
            break
        n += bloco[i]
    num_bytes = ""
    for i in range(len(bloco)):
        if bloco[i] == "*":
            bloco = bloco[i+1:]
            break
        num_bytes += bloco[i]
    num_bytes_seed = ""
    seed = ""
    for i in range(len(bloco)):
        if bloco[i] == "*":
            seed = bloco[i+1:]
            break
        num_bytes_seed += bloco[i]
    e_hex = hex(int(e))
    n_hex = hex(int(n))
    # retorna os parâmetros em base64
    return int(output_string), e_hex, n_hex, int(num_bytes), int(num_bytes_seed), int(seed)