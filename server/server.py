import queue, re
import socket, select, time
from oscrypto import asymmetric
import os, binascii


class User:
    def __init__(self, username, user_socket, public_key):
        self.username = username
        self.socket = user_socket
        self.public_key = public_key

    def __str__(self):
        return self.username


class CryptServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 2705
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(16)
        self.socks = [self.server]
        self.waitingPublicKey = []
        self.users = {}
        self.pair = asymmetric.generate_pair("rsa", 2048)
        self.now = time.time()
        self.message_queue = queue.Queue()
        self.running = False

    def command_setNick(self, user, commandArgs):
        oldname = user.username
        user.username = commandArgs[1]
        self.all_but(user, oldname + " is now known as " + user.username)
        return "Your Nickname is now " + user.username

    def command_who(self,user,commandArgs):
        return "Connected:" + ','.join(map(str, self.users.values()))

    def encrypt(self, user, message):
        return asymmetric.rsa_pkcs1v15_encrypt(user.public_key, message)

    def decrypt(self, message):
        return asymmetric.rsa_pkcs1v15_decrypt(self.pair[1], message)

    def encode(self, message):
        return message.encode("utf8")

    def decode(self, message):
        return message.decode("utf8")

    def getMessage(self, message):
        return self.decode(self.decrypt(message))

    def sendTo(self, user, message):
        user.socket.send(self.encrypt(user, self.encode(message)))

    def send_to_all(self, message):
        for user in self.users.values():
            self.sendTo(user, message)

    def all_but(self, userB, message):
        for user in self.users.values():
            if user is not userB:
                self.sendTo(user, message)

    def run(self):
        self.running = True
        while self.running:
            readable, writable, exceptions = select.select(self.socks, [], [], 0)
            for readableSocket in readable:
                if readableSocket == self.server:
                    client, addr = self.server.accept()
                    self.socks.append(client)
                    self.waitingPublicKey.append(client)
                    client.send(self.pair[0].asn1.dump())
                else:
                    try:
                        data = readableSocket.recv(2048)
                    except ConnectionResetError:
                        data = 0

                    if data:
                        if self.waitingPublicKey.__contains__(readableSocket):
                            clientPubKey = asymmetric.load_public_key(data)
                            rand = binascii.b2a_hex(os.urandom(3))
                            user = User("usr_" + rand.decode("ascii"), readableSocket, clientPubKey)
                            self.all_but(user, user.username + " has joined.")
                            self.users[str(readableSocket.getpeername()[1])] = user
                            self.waitingPublicKey.remove(readableSocket)
                        else:
                            data = self.getMessage(data)
                            user = self.users[str(readableSocket.getpeername()[1])]
                            isCommand = data.startswith("/")
                            if isCommand:
                                if data.startswith("/nick"):
                                    args = data.split(" ")
                                    result = self.command_setNick(user, args)
                                    self.sendTo(user, result)
                                if data.startswith("/who"):
                                    args = data.split(" ")
                                    result = self.command_who(user, args)
                                    self.sendTo(user, result)
                            else:
                                msg = "[" + user.username + "]" + data
                                self.all_but(user, msg)
                    else:
                        user = self.users[str(readableSocket.getpeername()[1])]
                        del self.users[str(readableSocket.getpeername()[1])]
                        readableSocket.close()
                        self.socks.remove(readableSocket)
                        self.all_but(readableSocket, user.username + " disconnected.")


CryptServer().run()
