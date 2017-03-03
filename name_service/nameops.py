import pybitcoin
from tx import sign_and_broadcast_tx
import virtualchain
from config import get_logger
from state_machine.operations import *

log = get_logger("nameops")

default_proxy = None
def set_default_proxy(proxy):
    global default_proxy
    default_proxy = proxy

def do_name_register(name, payment_privkey_info, reveal_address, utxo_client, tx_broadcaster, consensus_hash=None, proxy=None, safety_check=None):
    try:
        payment_address = virtualchain.BitcoinPrivateKey(payment_privkey_info).public_key().address()
    except Exception, e:
        log.error("Invalid private key info")
        return {'error': 'Name register can only use a single private key with a P2PKH script'}
    try:
        unsigned_tx = name_register_tx(name, reveal_address, consensus_hash, payment_address, utxo_client)
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to create name register tx")
        return {'error': 'Failed to create name register tx'}

    resp = {}

    try:
        resp = sign_and_broadcast_tx(unsigned_tx, payment_privkey_info, tx_broadcaster)
    except Exception, e:
        log.exception(e)
        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast namespace preorder transaction'}

    return resp


def do_name_update():
    pass

def do_name_revoke():
    pass

def do_name_transfer():
    pass



def name_register_tx(name, reveal_address, consensus_hash, payment_address, utxo_client):
    inputs, outputs = make_tx_name_register(name, reveal_address, consensus_hash, payment_address, utxo_client)
    log.info("input is: %s" % inputs)
    log.info("output is: %s" % outputs)
    return pybitcoin.serialize_transaction(inputs, outputs)

