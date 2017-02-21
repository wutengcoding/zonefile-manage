from  state_machine.script import *
from config import get_bitcoin_regtest_opts
from pybitcoin import serialize_transaction, sign_all_unsigned_inputs, broadcast_transaction
import virtualchain
import os

def sign_and_broadcast_tx(tx_hex, private_key_info):
    signed_tx = sign_tx(tx_hex, private_key_info)
    try:
        resp = broadcast_tx(signed_tx)
    except Exception, e:
        log.exception(e)
        log.error("Failed to broadcast transaction %s" % signed_tx)
        return {'error': 'Failed to broadcast transaction (caught exception)'}

    if 'error' in resp:
        log.error("Failed to broadcast transaction: %s" % resp['error'])

    return resp

def sign_tx(tx_hex, private_key_info):
    """
    Sign a transaction
    """
    return tx_sign_all_unsigned_inputs( private_key_info, tx_hex )



def broadcast_tx( tx_hex, tx_broadcaster=None ):
    """
    Send a signed transaction to the blockchain
    """
    if tx_broadcaster is None:
        tx_broadcaster = get_tx_broadcaster(  )

    if os.environ.get("BLOCKSTACK_TEST") == "1":
        log.debug("Send %s" % tx_hex)

    resp = {}
    try:
        resp = broadcast_transaction( tx_hex, tx_broadcaster )
        if 'tx_hash' not in resp or 'error' in resp:
            log.error("Failed to send %s" % tx_hex)
            resp['error'] = 'Failed to broadcast transaction: %s' % tx_hex
            return resp

    except Exception, e:
        log.exception(e)
        resp['error'] = 'Failed to broadcast transaction: %s' % tx_hex

        if os.environ.get("BLOCKSTACK_TEST") == "1":
            # should NEVER happen in test mode
            log.error("FATAL: failed to send transaction:\n%s" % simplejson.dumps(resp, indent=4, sort_keys=True))
            sys.exit(1)

    # for compatibility
    resp['transaction_hash'] = resp['tx_hash']
    del resp['tx_hash']
    return resp


def get_tx_broadcaster():
    utxo_opts = get_bitcoin_regtest_opts()
    return pybitcoin.BitcoindClient(utxo_opts['rpc_username'], utxo_opts['rpc_password'],
                                    use_https=utxo_opts['use_https'], server=utxo_opts['server'],
                                    port=utxo_opts['port'], version_byte=virtualchain.version_byte)
