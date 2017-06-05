import socket
from time import sleep
from threading import Thread
from .packets import *
from .auth import authorize
from .encrypt import MT5AES

MT5_CONN_TIMEOUT = 111
MT5_RECV_BUFFER = 2048

class Connection(object):
    """
    MT5 socket connection wrapper.
    """

    def __init__(self, mt5server, mt5port, login, password, encrypted=True):
        self.mt5server = mt5server
        self.mt5port = mt5port
        self.login = login
        self.password = password
        self.socket = socket.create_connection((mt5server, mt5port), 10)
        self.is_closed = False
        self.is_encrypted = encrypted
        self.is_authorized = False

        # Authenticate
        self.write("MT5WEBAPI")
        p = authorize(self, login, password, encrypted)

        # Crypto
        self.crypter = MT5AES(password, p.params['CRYPT_RAND'])
        self.is_authorized = True

        # Keep connection
        self.keep_alive_thread = Thread(target=self.keep_alive, name="MT5ConnKeepAlive")
        self.keep_alive_thread.start()

    def close(self):
        self.is_closed = True
        try:
            self.send(MT5Packet(cmd="QUIT"))
        except:
            # ignore socket problems
            pass
        finally:
            self.socket.close()

    def keep_alive(self):
        while not self.is_closed:
            self.send(MT5Packet(cmd="PING"), self.crypter)
            sleep(MT5_CONN_TIMEOUT)
    
    def read(self):
        """
        Read raw bytes from socket.
        Returns string.
        """
        data = self.socket.recv(MT5_RECV_BUFFER)
        log.debug("Raw recv: {}".format(data))
        return data

    def write(self, data):
        """
        Write raw bytes to socket.
        Returns number of sent bytes.
        """
        log.debug("Raw send: {}".format(data))
        return self.socket.send(data)

    def send(self, packet):
        self.write(packet.compose(self.crypter if self.is_authorized else None))

    def recv(self):
        return MT5Packet.parse(self.read(), 
                self.crypter if self.is_authorized else None)

    def __str__(self):
        return "MT5 Connection {user}@{server}:{port}".format(
            user=self.login, server=self.mt5server, port=self.mt5port
        )
