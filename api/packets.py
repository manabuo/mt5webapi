import re
import sys
from json import loads

from logging import getLogger
log = getLogger(__name__)

MAX_LENGTH = 64<<10 # 64Kb is enough for everybody

class MT5Packet(object):
    """
    Packet object: contains mt5 cmd, parameters, json body.
    """
    def __init__(self, cmd, params={}, body={}, num=1, flag=0):
        """
        Constructor.
        """
        assert(isinstance(cmd, str))
        assert(isinstance(params, dict))
        assert(isinstance(body, dict)) # must be json
        assert(isinstance(num,int))
        assert(isinstance(flag,int))
        self.cmd = cmd
        self.params = params
        self.body = body
        self.num = num
        self.flag = flag
        self.pkg_body = None

    def _format_pkg_body(self):
        cmd = self.cmd + '|' if self.params else self.cmd
        for p,v in self.params.iteritems():
            cmd += "{0}={1}|".format(escape(p), escape(str(v)))
        cmd += "\r\n{}\r\n".format(self.body)
        return cmd

    def compose(self, crypter=None):
        if self.pkg_body:
            return self.pkg_body
        pkg_body = self._format_pkg_body()
        assert len(pkg_body) < MAX_LENGTH
        pkg_body = pkg_body.encode('utf-16le')
        if crypter:
            pkg_body = crypter.encrypt(pkg_body)
        log.debug("pkg_body={}".format(pkg_body))

        h1 = '{:04x}'.format(len(pkg_body))
        h2 = '{:04x}'.format(self.num)
        h3 = '0'
        self.pkg_body = '{h1}{h2}{h3}{pkg_body}'.format(**locals())
        return self.pkg_body

    @staticmethod
    def get_nonping(packets):
        """
        Return first actual packet from mt5 noise.
        """
        for p in packets:
            if p.cmd != "PING": return p

    @staticmethod
    def parse(data, crypter=None):
        result = []
        i = 0
        log.debug("Parsing: {}".format(data))
        while i < len(data):
            log.debug("Processing next packet")
            log.debug("i={}".format(i))
            header = data[i:i+9]
            body_len = int(header[:4], base=16)
            packet_num = int(header[4:8], base=16)
            packet_flag = int(header[8:])
            log.debug('packet_num={0} packet_flag={1} body_len={2}'
                    .format(packet_num, packet_flag, body_len))
            i += 9
            body = data[i:i+body_len]
            if crypter:
                body = crypter.decrypt(body)
            assert packet_flag == 0 # Not ready yet for multipackets

            if not body: 
                result.append( 
                        MT5Packet('PING', {}, {}, packet_num, packet_flag) )
            else:
                body = body.decode('utf-16le').encode('utf-8')
                fields = body.split('|')
                cmd = fields[0]
                params = dict(f.split('=') for f in fields[1:-1])
                body = fields[-1].strip().replace('\x00','')
                log.debug("body={}".format(body))
                body = loads(body) if body else {}
                result.append( MT5Packet(cmd, params, body, 
                    packet_num, packet_flag) )
            i += body_len

        return result

def escape(s):
    # regexp magic with many slashes
    # escapes \n,|,\,= 
    # see https://support.metaquotes.net/ru/docs/mt5/api/webapi_screening
    log.debug("Escaping {}".format(s))
    return re.sub("([\n|=\\\\])", "\\\\\g<1>", s)


