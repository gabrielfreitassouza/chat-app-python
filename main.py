# Importações necessarias:
import tkinter as tk
from tkinter import ttk
import random
import socket
import threading
from datetime import datetime

# Definição do IP/PORTAS do servidor:
SERVER_IP = "127.0.0.1"
SERVER_TCP_PORT = 12345
SERVER_UDP_PORT = 23456

# Definição do IP/PORTAS do app:
APP_IP = "127.0.0.2"
APP_TCP_PORT = 34567
APP_UDP_PORT = 45689


class ChatApp:
    # Método de inicialização:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat")

        # Define a fonte para todo mundo:
        self.fonte = ("Arial", 12)

        # Frases para resposta automatica:
        self.auto_quotes = [
            "O ponto de partida de toda a realização é o desejo.\n",
            "O medo, a dúvida e a falta de autoconfiança são inimigos mortais da realização.\n",
            "O que a mente do homem pode conceber e acreditar, ela pode alcançar.\n",
            "Nossas únicas limitações são as que estabelecemos em nossas próprias mentes.\n",
            "Uma meta é um sonho com um prazo.\n",
            "Você é o mestre de seu destino, e o capitão de sua alma.\n",
            "Você pode ter sucesso em quase tudo que pode imaginar, se quiser.\n",
            "A persistência é essencial para o sucesso.\n",
        ]

        # Cria as abas:
        self.notebook = ttk.Notebook(self.root)
        self.tab_client = tk.Frame(self.notebook)
        self.tab_admin = tk.Frame(self.notebook)
        self.tab_client_history = tk.Frame(self.notebook)  # Adicione esta linha
        self.tab_admin_history = tk.Frame(self.notebook)
        self.notebook.add(self.tab_client, text="Cliente")
        self.notebook.add(self.tab_admin, text="Administrador")
        self.notebook.add(self.tab_client_history, text="Histórico do Cliente")
        self.notebook.add(self.tab_admin_history, text="Histórico do Administrador")
        self.notebook.pack(fill="both", expand=True)
        self.tab_logs = tk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="Logs")

        # Cria os widgets da aba do cliente:
        self.chat_client_frame = tk.Frame(self.tab_client)
        self.chat_client_frame.pack(fill="both", expand=True)
        self.scrollbar_client = tk.Scrollbar(self.chat_client_frame)
        self.scrollbar_client.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_client = tk.Text(self.chat_client_frame, yscrollcommand=self.scrollbar_client.set, state=tk.DISABLED,
                                   font=self.fonte)
        self.chat_client.pack(fill="both", expand=True)
        self.scrollbar_client.config(command=self.chat_client.yview)
        self.label_client_message = ttk.Label(self.tab_client, text="Digite a mensagem:", font=self.fonte)
        self.label_client_message.pack(pady=10)
        self.entry_client_message = tk.Text(self.tab_client, height=3, font=('Arial', 12))
        self.entry_client_message.pack(pady=10)

        self.button_client_send = ttk.Button(self.tab_client, text="Enviar", command=self.send_client_message)
        self.button_client_send.pack(pady=10)
        self.client_protocol_var = tk.StringVar()
        self.client_protocol_var.set("TCP")
        self.client_tcp_button = ttk.Radiobutton(self.tab_client, text="TCP", variable=self.client_protocol_var,
                                                 value="TCP")
        self.client_tcp_button.pack(pady=10)
        self.client_udp_button = ttk.Radiobutton(self.tab_client, text="UDP", variable=self.client_protocol_var,
                                                 value="UDP")
        self.client_udp_button.pack(pady=10)

        # Cria os widgets da aba do administrador:
        self.chat_admin_frame = tk.Frame(self.tab_admin)
        self.chat_admin_frame.pack(fill="both", expand=True)
        self.scrollbar_admin = tk.Scrollbar(self.chat_admin_frame)
        self.scrollbar_admin.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_admin = tk.Text(self.chat_admin_frame, yscrollcommand=self.scrollbar_admin.set, state=tk.DISABLED,
                                  font=self.fonte)
        self.chat_admin.pack(fill="both", expand=True)
        self.scrollbar_admin.config(command=self.chat_admin.yview)
        self.label_admin_message = ttk.Label(self.tab_admin, text="Digite a mensagem:", font=self.fonte)
        self.label_admin_message.pack(pady=10)
        self.entry_admin_message = tk.Text(self.tab_admin, height=3, font=('Arial', 12))
        self.entry_admin_message.pack(pady=10)
        self.button_admin_send = ttk.Button(self.tab_admin, text="Enviar", command=self.send_admin_message)
        self.button_admin_send.pack(pady=10)
        self.auto_response_var = tk.BooleanVar()
        self.auto_response_check = ttk.Checkbutton(self.tab_admin, text="Resposta Automática",
                                                   variable=self.auto_response_var)
        self.auto_response_check.pack(pady=10)
        self.protocol_var = tk.StringVar()
        self.protocol_var.set("TCP")
        self.tcp_button = ttk.Radiobutton(self.tab_admin, text="TCP", variable=self.protocol_var, value="TCP")
        self.tcp_button.pack(pady=10)
        self.udp_button = ttk.Radiobutton(self.tab_admin, text="UDP", variable=self.protocol_var, value="UDP")
        self.udp_button.pack(pady=10)

        # Cria os widgets da aba de histórico de mensagens Cliente:
        self.treeview_client_history = ttk.Treeview(self.tab_client_history, columns=("client_protocol", "client_msg"))
        self.treeview_client_history.heading("#0", text="Hora")
        self.treeview_client_history.heading("client_protocol", text="Protocolo Cliente")
        self.treeview_client_history.heading("client_msg", text="Mensagem do cliente")
        self.treeview_client_history.pack(expand=True, fill=tk.BOTH)
        scrollbar_client_history = ttk.Scrollbar(self.tab_client_history, orient="vertical",
                                                 command=self.treeview_client_history.yview)
        self.treeview_client_history.configure(yscrollcommand=scrollbar_client_history.set)
        self.treeview_client_history.pack(side="left", fill="both", expand=True)
        scrollbar_client_history.pack(side="right", fill="y")

        # Cria os widgets da aba de histórico de mensagens Administrador:
        self.treeview_admin_history = ttk.Treeview(self.tab_admin_history, columns=("admin_protocol", "admin_msg"))
        self.treeview_admin_history.heading("#0", text="Hora")
        self.treeview_admin_history.heading("admin_protocol", text="Protocolo Administrador")
        self.treeview_admin_history.heading("admin_msg", text="Mensagem do administrador")
        self.treeview_admin_history.pack(expand=True, fill=tk.BOTH)
        scrollbar_admin_history = ttk.Scrollbar(self.tab_admin_history, orient="vertical",
                                                command=self.treeview_admin_history.yview)
        self.treeview_admin_history.configure(yscrollcommand=scrollbar_admin_history.set)
        self.treeview_admin_history.pack(side="left", fill="both", expand=True)
        scrollbar_admin_history.pack(side="right", fill="y")

        # Cria os widgets da aba de logs:
        self.logs_frame = tk.Frame(self.tab_logs)
        self.logs_frame.pack(fill="both", expand=True)
        self.scrollbar_logs = tk.Scrollbar(self.logs_frame)
        self.scrollbar_logs.pack(side=tk.RIGHT, fill=tk.Y)
        self.logs = tk.Text(self.logs_frame, yscrollcommand=self.scrollbar_logs.set, state=tk.DISABLED,
                            font=self.fonte)
        self.logs.pack(fill="both", expand=True)
        self.scrollbar_logs.config(command=self.chat_client.yview)

    # Funções de envio de mensagens:
    def send_client_message(self):
        message = "Cliente: " + self.entry_client_message.get("1.0", tk.END)
        self.entry_client_message.delete("1.0", tk.END)
        client_protocol = self.client_protocol_var.get()
        if client_protocol == "TCP":
            self.send_message_tcp(message)
        else:
            self.send_message_udp(message)
        self.add_client_message_to_chats_and_history(message, client_protocol)
        if self.auto_response_var.get():
            self.send_auto_response()

    def send_admin_message(self):
        message = "Administrador: " + self.entry_admin_message.get("1.0",
                                                                   tk.END)
        self.entry_admin_message.delete("1.0", tk.END)
        admin_protocol = self.protocol_var.get()
        if admin_protocol == "TCP":
            self.send_message_tcp(message)
        else:
            self.send_message_udp(message)
        self.add_admin_message_to_chats_and_history(message, admin_protocol)

    def send_auto_response(self):
        message = random.choice(self.auto_quotes)
        admin_protocol = self.protocol_var.get()
        if admin_protocol == "TCP":
            self.send_message_tcp("Administrador: " + message)
        else:
            self.send_message_udp("Administrador: " + message)
        self.add_admin_message_to_chats_and_history(message, admin_protocol)

    def send_message_tcp(self, message):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_TCP_PORT))
            s.sendall(message.encode("utf-8"))
            s.close()
        except socket.error as e:
            message = "[app : {datetime.now().strftime('%H:%M:%S')}] Erro ao enviar mensagem via TCP:" + e
            self.log_message(message)

    def send_message_udp(self, message):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(message.encode("utf-8"), (SERVER_IP, SERVER_UDP_PORT))
            s.close()
        except socket.error as e:
            message = "[app : {datetime.now().strftime('%H:%M:%S')}] Erro ao enviar mensagem via UDP:" + e
            self.log_message(message)

    # Funções de recebimento de mensagens:
    def listen_for_messages_udp(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((APP_IP, APP_UDP_PORT))

        while True:
            data, addr = server.recvfrom(1024)
            message = data.decode("utf-8")

            if message.startswith("Cliente"):
                sender = "Cliente"
                senderLog = "Administrador"
                message = message[9:]
            else:
                sender = "Administrador"
                senderLog = "Cliente"
                message = message[14:]

            message_log = f"(udp) [{senderLog} : {datetime.now().strftime('%H:%M:%S')}] Mensagem recebida de {addr[0]}:{addr[1]}: {message}"
            self.log_message(message_log)
            self.add_received_message_to_chats_and_history(sender, message)

    def listen_for_messages_tcp(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((APP_IP, APP_TCP_PORT))
        server.listen(5)
        message = f"(tcp) [app : {datetime.now().strftime('%H:%M:%S')}] Escutando em {SERVER_IP}:{SERVER_TCP_PORT}"
        self.log_message(message)

        while True:
            client, addr = server.accept()
            message = f"(tcp) [app : {datetime.now().strftime('%H:%M:%S')}] Conexão aceita de {addr[0]}:{addr[1]}"
            self.log_message(message)
            client_handler = threading.Thread(target=self.handle_client_tcp, args=(client, addr))
            client_handler.start()

    def handle_client_tcp(self, client_socket, addr):
        data = client_socket.recv(1024)
        message = data.decode("utf-8")

        if message.startswith("Cliente"):
            sender = "Cliente"
            senderLog = "Administrador"
            message = message[9:]
        else:
            sender = "Administrador"
            senderLog = "Cliente"
            message = message[14:]

        menssage_log = f"(tcp) [{senderLog} : {datetime.now().strftime('%H:%M:%S')}] Mensagem recebida de {addr[0]}:{addr[1]}: {message}"
        self.log_message(menssage_log)
        self.add_received_message_to_chats_and_history(sender, message)
        client_socket.close()

    def add_received_message_to_chats_and_history(self, sender, message):
        if (sender == "Cliente"):
            self.chat_client.config(state=tk.NORMAL)
            self.chat_client.insert(tk.END, f"Você: {message}\n")
            self.chat_client.config(state=tk.DISABLED)
        else:
            self.chat_client.config(state=tk.NORMAL)
            self.chat_client.insert(tk.END, f"{sender}: {message}\n")
            self.chat_client.config(state=tk.DISABLED)

        if (sender == "Administrador"):
            self.chat_admin.config(state=tk.NORMAL)
            self.chat_admin.insert(tk.END, f"Você: {message}\n")
            self.chat_admin.config(state=tk.DISABLED)
        else:
            self.chat_admin.config(state=tk.NORMAL)
            self.chat_admin.insert(tk.END, f"{sender}: {message}\n")
            self.chat_admin.config(state=tk.DISABLED)

    # Funções de adição de mensagens a janelas e históricos:
    def add_client_message_to_chats_and_history(self, message, client_protocol):
        self.treeview_client_history.insert("", tk.END, text=datetime.now().strftime("%H:%M:%S"),
                                            values=(client_protocol, message[9:]))

    def add_admin_message_to_chats_and_history(self, message, admin_protocol):
        self.treeview_admin_history.insert("", tk.END, text=datetime.now().strftime("%H:%M:%S"),
                                           values=(admin_protocol, message[14:]))

    # Funções de inicialização de escuta de protocolos:
    def start_listening_udp(self):
        self.listen_thread_udp = threading.Thread(target=self.listen_for_messages_udp)
        self.listen_thread_udp.daemon = True
        self.listen_thread_udp.start()

    def start_listening_tcp(self):
        self.listen_thread = threading.Thread(target=self.listen_for_messages_tcp)
        self.listen_thread.daemon = True
        self.listen_thread.start()

    # Funções de log e processamento de mensagens:
    def log_message(self, message):
        self.logs.config(state=tk.NORMAL)
        self.logs.insert(tk.END, message + "\n\n")
        self.logs.config(state=tk.DISABLED)

    def process_received_message(self, message):
        self.log_message(message)


class ChatServer:

    def __init__(self, ip, port_tcp, port_udp, callback):
        self.ip = ip
        self.port_tcp = port_tcp
        self.port_udp = port_udp
        self.callback = callback

    # Funções TCP:
    def run_tcp(self):
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.bind((self.ip, self.port_tcp))
        tcp_server.listen(5)
        message = f"(tcp) [server : {datetime.now().strftime('%H:%M:%S')}]   Escutando em {self.ip}:{self.port_tcp}"
        self.callback(message)

        while True:
            client, addr = tcp_server.accept()
            message = f"(tcp) [server : {datetime.now().strftime('%H:%M:%S')}]   Conexão aceita de {addr[0]}:{addr[1]}"
            self.callback(message)
            client_handler = threading.Thread(target=self.handle_tcp_client, args=(client, addr))
            client_handler.start()

    def handle_tcp_client(self, client_socket, addr):
        data = client_socket.recv(1024)
        message = f"(tcp) [server : {datetime.now().strftime('%H:%M:%S')}]   Mensagem recebida de {addr[0]}:{addr[1]}: {data.decode('utf-8')}"
        self.callback(message)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((APP_IP, APP_TCP_PORT))
            s.sendall(data)
            s.close()
        client_socket.close()

    # Funções UDP:
    def run_udp(self):
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind((self.ip, self.port_udp))

        while True:
            data, addr = udp_server.recvfrom(1024)
            message = f"(udp) [server : {datetime.now().strftime('%H:%M:%S')}]   Mensagem recebida de {addr[0]}:{addr[1]}: {data.decode('utf-8')}"
            self.callback(message)
            self.handle_udp_client(udp_server, data, addr)

    def handle_udp_client(self, udp_server, data, addr):
        message = data.decode("utf-8")
        self.callback(
            f"(udp) [server : {datetime.now().strftime('%H:%M:%S')}]   Mensagem recebida de {addr[0]}:{addr[1]}: {message}")

        udp_server.sendto(data, (APP_IP, APP_UDP_PORT))


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    chat_server = ChatServer(SERVER_IP, SERVER_TCP_PORT, SERVER_UDP_PORT, app.process_received_message)
    server_thread = threading.Thread(target=chat_server.run_tcp)
    server_thread.start()
    server_thread_udp = threading.Thread(target=chat_server.run_udp)
    server_thread_udp.start()
    app.start_listening_udp()
    app.start_listening_tcp()
    root.mainloop()
