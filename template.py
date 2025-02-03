import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import assinatura
from rsa import gera_chaves


class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Assinatura Digital")

        self.mensagem = ""
        self.path = ""
        self.n = None
        self.d = None
        self.e = None
        self.bits = 1024

        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Escolha uma opção:")
        self.label.pack()

        self.button_gerar_chaves = tk.Button(self.root, text="Gerar Chaves", command=self.gerar_chaves)
        self.button_gerar_chaves.pack()

        self.button_assinar = tk.Button(self.root, text="Assinar", command=self.assina)
        self.button_assinar.pack()

        self.button_verificar = tk.Button(self.root, text="Verificar Assinatura", command=self.verifica)
        self.button_verificar.pack()

        self.button_sair = tk.Button(self.root, text="Sair", command=self.root.quit)
        self.button_sair.pack()

        self.text_output = tk.Text(self.root, height=10, width=50)
        self.text_output.pack()

    def print_to_gui(self, text):
        self.text_output.insert(tk.END, text + "\n")
        self.text_output.see(tk.END)

    def verifica_chaves(self):
        if self.e is not None and self.d is not None and self.n is not None:
            return True
        else:
            self.print_to_gui("Não foram encontradas chaves salvas.")
            self.print_to_gui("Você poderia digitar as chaves?")
            self.n = self.get_input("Digite a chave n:")
            self.d = self.get_input("Digite a chave d:")
            self.e = self.get_input("Digite a chave e:")
            return True

    def get_input(self, prompt):
        return simpledialog.askstring("Input", prompt)

    def gerar_chaves(self):
        if self.e is not None and self.d is not None and self.n is not None:
            if not messagebox.askyesno("Aviso", "Já existem chaves salvas, deseja sobrescrever?"):
                return

        self.bits = int(self.get_input("Número de bits da chave (default 1024):") or 1024)
        t = int(self.get_input("Número de repetições (default 100):") or 100)

        self.print_to_gui("Por favor, aguarde...")
        self.n, self.d, self.e = gera_chaves(self.bits, t)

        self.print_to_gui("Chaves geradas:")
        self.print_to_gui(f"Chave pública/privada n: {self.n}")
        self.print_to_gui(f"Expoente público e: {self.e}")
        self.print_to_gui(f"Chave privada d: {self.d}")

    def assina_texto(self):
        self.mensagem = self.get_input("Digite a mensagem:")
        mensagem_assinada_base64, assinatura_hex = assinatura.assina_string(self.n, self.d, self.e, self.mensagem,
                                                                            self.bits)

        self.print_to_gui("Mensagem assinada em Base64:")
        self.print_to_gui(mensagem_assinada_base64)
        self.print_to_gui("Assinatura:")
        self.print_to_gui(assinatura_hex)

    def assina_arquivo(self):
        self.path = filedialog.askopenfilename(title="Selecione o arquivo para assinar")
        if not self.path:
            return
        mensagem_assinada_base64, assinatura_hex = assinatura.assina_arquivo(self.n, self.d, self.e, self.path,
                                                                             self.bits)

        self.print_to_gui("Mensagem assinada em Base64:")
        self.print_to_gui(mensagem_assinada_base64)
        self.print_to_gui("Assinatura:")
        self.print_to_gui(assinatura_hex)

    def assina(self):
        if not self.verifica_chaves():
            return

        option = messagebox.askquestion("Assinar", "Deseja digitar a mensagem? Caso não, você poderá selecionar o arquivo.")
        if option == 'yes':
            self.assina_texto()
        else:
            self.assina_arquivo()

    def verifica_texto(self):
        mensagem_assinada = self.get_input("Digite a mensagem assinada:")
        assinatura_hex = self.get_input("Digite a assinatura da mensagem:")

        self.print_to_gui("Verificando...")
        try:
            if not assinatura.verifica_assinatura_string(mensagem_assinada, assinatura_hex):
                raise ValueError("Erro: assinatura incorreta")
            self.print_to_gui("Assinatura correta")
        except ValueError as e:
            self.print_to_gui(f"Assinatura incorreta: {e}")

    def verifica_arquivo(self):
        mensagem_assinada = filedialog.askopenfilename(title="Selecione o arquivo da mensagem assinada em Base64")
        assinatura_hex = filedialog.askopenfilename(title="Selecione o arquivo da assinatura")

        self.print_to_gui("Verificando...")
        try:
            if not assinatura.verifica_assinatura_arquivo(mensagem_assinada, assinatura_hex):
                raise ValueError("Erro: assinatura incorreta")
            self.print_to_gui("Assinatura correta")
        except ValueError as e:
            self.print_to_gui(f"Assinatura incorreta: {e}")

    def verifica(self):
        if not self.verifica_chaves():
            return

        option = messagebox.askquestion("Verificar", "Deseja digitar a mensagem assinada? Caso não, você poderá selecionar o arquivo.")
        if option == 'yes':
            self.verifica_texto()
        else:
            self.verifica_arquivo()


if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()