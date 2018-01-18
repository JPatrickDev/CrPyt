import socket, queue, threading, sys, select

import time
from oscrypto import asymmetric
import os


class CrPytClient:

    def __init__(self, host, port):
        self.socket = socket.socket()
        self.host = host
        self.port = port
        self.message_queue = queue.Queue()
        self.running = False
        self.pair = asymmetric.generate_pair("rsa", 2048)
        self.server_public_key = None
        self.firstRun = True

    def command_setNick(self, user, commandArgs):
        user.username = commandArgs[1]
        return "Your Nickname is now " + user.username

    def handleInput(self):
        while self.running:
            self.message_queue.put(input(""))

    def encrypt(self, message):
        return asymmetric.rsa_pkcs1v15_encrypt(self.server_public_key, message)

    def decrypt(self, message):
        return asymmetric.rsa_pkcs1v15_decrypt(self.pair[1], message)

    def encode(self, message):
        return message.encode("utf8")

    def decode(self, message):
        return message.decode("utf8")

    def send(self, message):
        self.socket.send(self.encrypt(self.encode(message)))

    def receive(self, message):
        return self.decode(self.decrypt(message))


    def run(self):
        os.system('cls')
        self.running = True
        self.socket.connect((self.host, self.port))
        self.socket.send(self.pair[0].asn1.dump())
        t = threading.Thread(target=self.handleInput)
        t.daemon = True
        t.start()
        #
        while self.running:
            time.sleep(0.01)
            read, write, error = select.select([self.socket], [], [], 0)
            for socket in read:
                if socket is self.socket:
                    data = socket.recv(4096)
                    if not data:
                        print("Disconnected from CrPyt server.")
                        sys.exit()
                    else:
                        if self.server_public_key is None:
                            self.server_public_key = asymmetric.load_public_key(data)
                            print("Server Public Key Fetched. Chat is now encrypted.")
                        else:
                            print(self.receive(data))
            if not self.message_queue.empty():
                msg = self.message_queue.get()
                if msg == "quit":
                    self.running = False
                    sys.exit()
                else:
                    self.send(msg)
            if self.firstRun:
                self.firstRun = False
                time.sleep(0.2)
                self.send("/who")
    #        time.sleep(0.01)


host = input("Server IP:")
CrPytClient(host, 2705).run()
