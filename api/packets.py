import re
import sys
from collections import namedtuple

from logging import getLogger
log = getLogger(__name__)

Packet = namedtuple('MT5Packet', ('cmd', 'params', 'body', 'num', 'flag', 'len'))

#### Base functions ####
MAX_LENGTH = 64<<10 # 64Kb is enough for everybody
def _make_packet(body, number):
    assert isinstance(body, str)
    assert isinstance(number, int)
    assert len(body) < MAX_LENGTH
    body = body.encode('utf-16le')
    log.debug("body={}".format(body))

    h1 = '{:04x}'.format(len(body))
    h2 = '{:04x}'.format(number)
    h3 = '0'
    return '{h1}{h2}{h3}{body}'.format(**locals())

def _format_cmd_body(command, params, body):
    cmd = command + '|' if params else command
    for p in params.keys():
        cmd += "{0}={1}|".format(escape(p), escape(str(params[p])))
    cmd += "\r\n{}\r\n".format(body)
    return cmd

def create_cmd_packet(num, command, params={}, body={}):
    return _make_packet(_format_cmd_body(command, params, body), num)

def parse_packets(data):
    result = []
    i = 0
    log.debug("recv_data={}".format(data))
    while i < len(data):
        log.debug("Processing next packet")
        log.debug("i={}".format(i))
        header = data[i:i+9]
        body_len = int(header[:4], base=16)
        packet_num = int(header[4:8], base=16)
        packet_flag = int(header[8:])
        log.debug('packet_num={0} packet_flag={1} body_len={2}'.format(packet_num, packet_flag,
            body_len))
        i += 9
        body = data[i:i+body_len]
        assert packet_flag == 0 # Not ready yet for multipackets

        if not body: 
            result.append( Packet('PING', {}, '', packet_num, packet_flag, body_len) )
        else:
            body = body.decode('utf-16le').encode('utf-8')
            fields = body.split('|')
            cmd = fields[0]
            params = dict(f.split('=') for f in fields[1:-1])
            body = fields[-1].strip()
            result.append( Packet(cmd, params, body, packet_num, packet_flag, body_len) )
        i += body_len

    return result

def escape(s):
    # regexp magic with many slashes
    # escapes \n,|,\,= 
    # see https://support.metaquotes.net/ru/docs/mt5/api/webapi_screening
    log.debug("Escaping {}".format(s))
    return re.sub("([\n|=\\\\])", "\\\\\g<1>", s)


#### Packets implementations ####
## Basic
def hello_packet():
    return 'MT5WEBAPI'

def ping_packet():
    return '000007770'

def close_packet():
    return create_cmd_packet(1, 'QUIT')

def test_access_packet():
    return create_cmd_packet(1, 'TEST_ACCESS')

def test_trade_packet():
    return create_cmd_packet(1, 'TEST_TRADE')

## Service
def server_restart_packet():
    return create_cmd_packet(1, 'SERVER_RESTART')

## Common
def common_get_packet():
    return create_cmd_packet(1, 'COMMON_GET')

## Time
def time_server_packet():
    return create_cmd_packet(1, 'TIME_SERVER')

def time_get_packet():
    return create_cmd_packet(1, 'TIME_GET')

## Groups
def group_add_packet(body):
    return create_cmd_packet(1, 'GROUP_ADD', body=body)

def group_delete_packet(group):
    return create_cmd_packet(1, 'GROUP_DELETE', params={'GROUP':group})

def group_total_packet():
    return create_cmd_packet(1, 'GROUP_TOTAL')

def group_next_packet(index):
    return create_cmd_packet(1, 'GROUP_NEXT', params={'INDEX':index})

def group_get_packet(group):
    return create_cmd_packet(1, 'GROUP_GET', params={'GROUP':group})

## Symbols
def symbol_add_packet(body):
    return create_cmd_packet(1, 'SYMBOL_ADD', body=body)

def symbol_delete_packet(symbol):
    return create_cmd_packet(1, 'SYMBOL_DELETE', params={'SYMBOL':symbol})

def symbol_total_packet():
    return create_cmd_packet(1, 'SYMBOL_TOTAL')

def symbol_next_packet(index):
    return create_cmd_packet(1, 'SYMBOL_NEXT', params={'INDEX':index})

def symbol_get_packet(symbol):
    return create_cmd_packet(1, 'SYMBOL_GET', params={'SYMBOL':symbol})

def symbol_get_group_packet(symbol, group):
    return create_cmd_packet(1, 'SYMBOL_GET_GROUP', params={'SYMBOL':symbol,'GROUP':group})

## Clients
def user_add_packet(pass_main, pass_investor, body):
    return create_cmd_packet(1, 'USER_ADD', params={'PASS_MAIN':pass_main,
        'PASS_INVESTOR':pass_investor}, body=body)

def user_update_packet(body):
    return create_cmd_packet(1, 'USER_UPDATE', body=body)

def user_delete_packet(user):
    return create_cmd_packet(1, 'USER_DELETE', params={'LOGIN':user})

def user_get_packet(user):
    return create_cmd_packet(1, 'USER_GET', params={'LOGIN':user})

def user_pass_check_packet(login, type, password):
    return create_cmd_packet(1, 'USER_PASS_CHECK', params={'LOGIN':login, 'TYPE':type,
        'PASSWORD':password})

def user_pass_change_packet(login, type, password):
    return create_cmd_packet(1, 'USER_PASS_CHANGE', params={'LOGIN':login, 'TYPE':type,
        'PASSWORD':password})

def user_accouont_get_packet(user):
    return create_cmd_packet(1, 'USER_ACCOUNT_GET', params={'LOGIN':user})

def user_logins_packet(group):
    return create_cmd_packet(1, 'USER_LOGINS', params={'GROUP':group})

## Orders
