from .packets import *
from .exceptions import MT5Error
from hashlib import md5
from uuid import uuid1

from logging import getLogger
log = getLogger(__name__)

def authorize(conn, login, password, encrypted):
    """
    Authorize client with given credentials through mt5 server connection.
    """
    log.info("Starting MT5 WebAPI auth for {}@{}".format(login, conn.mt5server))
    # Work only with unicode
    assert isinstance(login, str) and isinstance(password, str)
    type = 'MANAGER'
    agent = 'Uptrader'
    version = 1571
    if encrypted:
        crypt_method = 'AES2560FB'
    else:
        crypt_method = 'NONE'

    packet = create_cmd_packet(1, 'AUTH_START', dict(LOGIN=login, VERSION=version, AGENT=agent,
        TYPE=type, CRYPT_METHOD=crypt_method))
    log.debug("AUTH_START: {}".format(packet))
    # send packet next
    conn.write_plain(packet)
    
    # recv packet
    packet = conn.read_plain()
    log.debug("AUTH_ANSWER: {}".format(packet))
    cmd, params, body = parse_cmd_packet(packet)
    # assert cmd=='AUTH_ANSWER' # maybe MT5Error
    retcode = params['RETCODE']
    if not retcode.startswith('0'):
        log.error("MT5 return code NOT OK - {}".format(retcode))
        raise MT5Error(retcode)
    srv_rand = params['SRV_RAND']
    cli_rand = uuid1().get_hex()
    srv_rand_answer = make_auth_answer_hash(password, srv_rand)
    
    packet = create_cmd_packet(1, 'AUTH_ANSWER', dict(SRV_RAND_ANSWER=srv_rand_answer,
        CLI_RAND=cli_rand))
    log.debug("AUTH_ANSWER2: {}".format(packet))
    # send packet
    conn.write_plain(packet)
    
    # recv packet
    packet = conn.read_plain()
    log.debug("AUTH_ANSWER3: {}".format(packet))
    return parse_cmd_packet(packet)

def make_auth_answer_hash(password, srv_rand):
    """
    Make SRV_RAND_ANSWER from PASSWORD and SRV_RAND.

    Example:
    password hash=MD5(MD5('Password1')+'WebAPI')=904ba8ecb16273d2f0ae9c3b8a023752
    SRV_RAND=73007dc7184747ce0f7c98516ef1c851
    //--- Calculation formula: SRV_RAND_ANSWER=MD5(password hash+SRV_RAND)
    SRV_RAND_ANSWER=MD5(904ba8ecb16273d2f0ae9c3b8a023752+73007dc7184747ce0f7c98516ef1c851)=77fe51827f7fa69dd80fbec9aa33f1bb
    """
    t1 = md5(password.encode('utf-16le')).digest()
    # important - no utf16 between hashes!
    t2 = 'WebAPI'
    pwd_hash = md5(t1 + t2).digest()

    # hex string from bytes
    srv_rand = srv_rand.decode('hex')
    srv_rand_answer = md5(pwd_hash + srv_rand).hexdigest()
    # return unicode
    return srv_rand_answer.decode()
