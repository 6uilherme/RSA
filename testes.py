import unittest
import hashlib
import rsa
import assinatura
import oaep

class MyTestCase(unittest.TestCase):

    def test_encripta_rsa_string(self):
        n, d, e = assinatura.gera_chaves()
        msg = "mensagem"
        msg_hex_cod = int(msg.encode('utf-8').hex(),16)
        c = assinatura.cifracao_rsa(msg_hex_cod, e, n)
        d = assinatura.decifracao_rsa(c, d, n)
        msg_dec = bytes.fromhex(hex(d)[2:]).decode('utf-8')
        self.assertEqual(msg, msg_dec)

    def test_assinatura_string(self):
        n, d, e = assinatura.gera_chaves()
        msg = "mensagem"
        assinatura_hash = hashlib.sha3_256(msg.encode('utf-8'))
        print("assinatura", assinatura)
        hash_hex = assinatura_hash.hexdigest()
        print("hash_hex", hash_hex)
        hash_int = int(hash_hex, 16)
        print("hash_int", hash_int)
        assinatura_dec = hex(hash_int)[2:]
        self.assertEqual(hash_hex, assinatura_dec)

    def test_oaep_main(self):
        oaep_teste = oaep.main_oaep()
        self.assertEqual(oaep_teste, True)

    def test_assinatura_main(self):
        assinatura_teste = assinatura.main_assinatura()
        self.assertEqual(assinatura_teste, True)

if __name__ == '__main__':
    unittest.main()
