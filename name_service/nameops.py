import xmlrpclib

import pybitcoin
import virtualchain
from config import get_logger
from state_machine.operations import *
from pybitcoin import broadcast_transaction
from virtualchain.bitcoin_blockchain.keys import *
from state_machine import nameset as state_engine
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
        signed_tx = name_register_tx(name, payment_privkey_info, reveal_address, consensus_hash, payment_address, utxo_client)
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to create name register tx")
        return {'error': 'Failed to create name register tx'}

    resp = {}

    try:
        resp = broadcast_transaction(signed_tx, tx_broadcaster)
    except Exception, e:
        log.exception(e)
        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast namespace preorder transaction'}

    return resp


def do_name_update(name, data_hash, payment_privkey_info):
    owner_address = get_privkey_info_address(payment_privkey_info)
    # Check ownership
    db = state_engine.get_readonly_db_state(disposition=state_engine.DISPOSITION_RO)
    records = db.get_name(name)

    pass

def do_name_revoke():
    pass

def do_name_transfer():
    pass



def name_register_tx(name, private_key, reveal_address, consensus_hash, payment_address, utxo_client):
    tx = make_tx_name_register(name, private_key, reveal_address, consensus_hash, payment_address, utxo_client)
    return tx


def get_name_record(name):
    s = xmlrpclib.ServerProxy('http://%s:%s' % ('0.0.0.0', RPC_SERVER_PORT))
    name_records = s.rpc_get_name(name)
    return name_records




