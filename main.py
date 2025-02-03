import assinatura
from rsa import gera_chaves


class Main:

    def __init__(self):
        self.mensagem = ""
        self.path = ""
        self.n = None
        self.d = None
        self.e = None
        self.bits = 1024

    def print_menu_inicial(self):
        print("Deseja voltar para o menu inicial?")
        print("1: sim")
        print("2: não (default)")
        n = input()
        if n == "1":
            return self.main()

    def verifica_chaves(self):
        if self.e is not None and self.d is not None and self.n is not None:
            pass
        else:
            print("Não foram encontradas chaves salvas.")
            print("Você poderia digitar as chaves?")
            print("1: digitar as chaves.")
            print("2: voltar ao menu inicial (default).")
            n = input()
            if n == "1":
                print("Digite a chave n:")
                self.n = input()
                print("Digite a chave d:")
                self.d = input()
                print("Digite a chave e:")
                self.e = input()
            else:
                return self.main()

    def gerar_chaves(self):
        if self.e is not None and self.d is not None and self.n is not None:
            print("Já existem chaves salvas, deseja prosseguir?")
            print("1: sobrescrever chaves salvas.")
            print("2: voltar menu inicial (default).")
            n = input()
            if n == "1":
                pass
            else:
                return self.main()
        print("Deseja definir parâmetros avançados?")
        print("1: sim")
        print("2: não (default)")
        n = input()
        if n == "1":
            print("Numero de bits da chave:")
            self.bits = input()
            print("Numero de repetições:")
            t = input()
            print("Por favor, aguarde")
            self.n, self.d, self.e = gera_chaves(int(self.bits), int(t))
        else:
            print("Por favor, aguarde")
            self.n, self.d, self.e = gera_chaves()
        print("Chaves geradas:")
        print("Chave pública/privada n:")
        print(self.n)
        print("Expoente público e:")
        print(self.e)
        print("Chave privada d:")
        print(self.d)
        self.print_menu_inicial()

    def assina_texto(self):
        print("Digite a mensagem: ")
        self.mensagem = input()
        n = input()
        # raliza a assinatura
        mensagem_assinada_base64, assinatura_hex = assinatura.assina_string(self.n, self.d, self.e, self.mensagem, self.bits)
        print("Mensagem assinada em Base64:")
        print(mensagem_assinada_base64)
        print("Assinatura:")
        print(assinatura_hex)
        return self.print_menu_inicial()

    def assina_arquivo(self):
        print("Digite o caminho do arquivo: ")
        self.path = input()
        # realiza a assinatura
        mensagem_assinada_base64, assinatura_hex = assinatura.assina_arquivo(self.n, self.d, self.e, self.path, self.bits)
        print("Mensagem assinada em Base64:")
        print(mensagem_assinada_base64)
        print("Assinatura:")
        print(assinatura_hex)
        return self.print_menu_inicial()


    def assina(self):
        self.verifica_chaves()
        print("Deseja digitar a mensagem ou utilizar um arquivo de texto?")
        print("1: digitar a mensagem.")
        print("2: utilizar arquivo de texto.")
        print("3: voltar para menu inicial (default).")
        n = input()
        if n == "1":
            return self.assina_texto()
        if n == "2":
            return self.assina_arquivo()
        else:
            return self.main()

    def verifica_texto(self):
        print("Digite a mensagem assinada: ")
        mensagem_assinada = input()
        print("Digite a assinatura da mensagem")
        assinatura_hex = input()
        print("Verificando...")
        try:
            if not assinatura.verifica_assinatura_string(mensagem_assinada, assinatura_hex):
                raise ValueError("Erro: assinatura incorreta")
            print("Assinatura correta")
        except ValueError as e:
            print("Assinatura incorreta:", e)
        return self.print_menu_inicial()

    def verifica_arquivo(self):
        print("Digite o caminho da mensagem assinada em Base64:")
        mensagem_assinada = input()
        print("Digite o caminho do arquivo da assinatura:")
        assinatura_hex = input()
        print("Verificando...")
        try:
            if not assinatura.verifica_assinatura_arquivo(mensagem_assinada, assinatura_hex):
                raise ValueError("Erro: assinatura incorreta")
            print("Assinatura correta")
        except ValueError as e:
            print("Assinatura incorreta:", e)
        return self.print_menu_inicial()


    def verifica(self):
        self.verifica_chaves()
        print("Deseja digitar a mensagem ou utilizar um arquivo de texto?")
        print("1: digitar a mensagem assinada em base 64.")
        print("2: utilizar arquivo de texto.")
        print("3: voltar para menu inicial (default).")
        n = input()
        if n == "1":
            return self.verifica_texto()
        if n == "2":
            return self.verifica_arquivo()
        else:
            return self.main()

    def main(self):
        print("Deseja gerar chaves, assinar ou verificar assinatura?")
        print("1: gerar chaves")
        print("2: assinar")
        print("3: verificar")
        print("4: sair (default).")
        n = input()
        if n == "1":
            return self.gerar_chaves()
        elif n == "2":
            return self.assina()
        elif n == "3":
            return self.verifica()
        else:
            return

Main().main()