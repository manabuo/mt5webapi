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
    # Work only with strings
    assert isinstance(login, str) and isinstance(password, str)
    type = 'MANAGER'
    agent = 'UpTrader'
    version = 1571
    if encrypted:
        crypt_method = 'AES256OFB'
    else:
        crypt_method = 'NONE'

    p = MT5Packet('AUTH_START', dict(LOGIN=login, VERSION=version, AGENT=agent,
        TYPE=type, CRYPT_METHOD=crypt_method))
    log.debug("AUTH_START: {}".format(p.params))
    # send packet next
    conn.send(p)

    # recv packets
    packets = conn.recv()
    p = MT5Packet.get_nonping(packets)
    log.debug("AUTH_ANSWER1: {}".format(p.params))
    assert p.cmd=='AUTH_START' # maybe MT5Error
    retcode = p.params['RETCODE']
    if not retcode.startswith('0'):
        log.error("MT5 return code NOT OK - {}".format(retcode))
        raise MT5Error(retcode)
    srv_rand = p.params['SRV_RAND']
    cli_rand = uuid1().get_hex()
    srv_rand_answer = make_auth_answer_hash(password, srv_rand)

    p = MT5Packet('AUTH_ANSWER', dict(SRV_RAND_ANSWER=srv_rand_answer,
        CLI_RAND=cli_rand))
    log.debug("AUTH_ANSWER2: {}".format(p.params))
    # send packet
    conn.send(p)

    # recv packet
    packets = conn.recv()
    p = MT5Packet.get_nonping(packets)
    log.debug("AUTH_ANSWER3: {}".format(p.pkg_body))
    log.info("Authorized succesfully!")
    return p

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
