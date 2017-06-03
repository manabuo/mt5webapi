import socket
from time import sleep
from threading import Thread
from .packets import *
from .auth import authorize
from .encrypt import MT5AES

MT5_CONN_TIMEOUT = 30
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

        # Authenticate
        self.write_plain(hello_packet())
        cmd, params, body = authorize(self, login, password, encrypted)

        # Crypto
        self.cypher = MT5AES(password, params['CRYPT_RAND'])

        # Keep connection
        self.keep_alive_thread = Thread(target=self.keep_alive, name="MT5ConnKeepAlive")
        self.keep_alive_thread.start()
        super(Connection, self).__init__()

    def close(self):
        self.is_closed = True
        try:
            self.write(close_packet())
        except:
            # ignore socket problems
            pass
        finally:
            self.socket.close()

    def keep_alive(self):
        while not self.is_closed:
            self.write(ping_packet())
            sleep(MT5_CONN_TIMEOUT)
    
    def read_plain(self):
        return self.socket.recv(MT5_RECV_BUFFER)

    def read(self):
        data = self.read_plain()
        log.debug("Raw recv: {}".format(data))
        if self.is_encrypted:
            return self.cypher.decrypt(data)
        else:
            return data

    def write_plain(self, data):
        return self.socket.send(data)

    def write(self, data):
        if self.is_encrypted:
            data = self.cypher.encrypt(data)
        log.debug("Raw send: {}".format(data))
        return self.write_plain(data)

    def __str__(self):
        return "MT5 Connection {user}@{server}:{port}".format(
            user=self.login, server=self.mt5server, port=self.mt5port
        )
