import os
import tempfile

import errno

import virtualchain
import keylib
from config import get_logger

log = get_logger("testlib")

snapshots_dir = None

class TestAPIProxy(object):
    def __init__(self):
        global utxo_opts

        client_path = os.environ.get("ZONEFILEMANAGE_CLIENT_CONFIG", None)
        assert client_path is not None



class Wallet(object):
    def __init__(self, pk_wif, ignored):

        pk = virtualchain.BitcoinPrivateKey(pk_wif)

        self._pk = pk

        if pk_wif.startswith("c"):
            #already a privkey
            self.privkey = pk_wif
        else:
            self.privkey = pk.to_wif()

        self.pubkey_hex = pk.public_key().to_hex()
        self.addr = pk.public_key().address()

        log.info("Wallet %s(%s)" % (self.privkey, self.addr))

class MultisigWallet(object):
    def __init__(self, m, *pks):

        self.privkey = virtualchain.make_multisig_info( m, pks )
        self.m = m
        self.n = len(pks)

        self.addr = self.privkey['address']

        log.info("Multisig wallet %s " % (self.addr))



def set_default_payment_wallet( w ):
    global default_payment_wallet
    default_payment_wallet = w

# set up for test environment
def set_utxo_opts( opts ):
    global utxo_opts
    utxo_opts = opts

def set_bitcoind( b ):
    global bitcoind
    bitcoind = b

def set_state_engine( s ):
    global state_eigine
    state_eigine = s



def next_block( **kw ):
    """
    Advance the mock blockchain by one block
    """
    global snapshots_dir, state_engine

    if snapshots_dir is None:
        snapshots_dir = tempfile.mkdtemp(prefix='zonefilemanage-test-databases-')

    del state_engine

    # Flush all transactions and reset state engine
    kw['next_block_upcall']()
    kw['sync_virtualchain_upcall']()



def zonefilemanage_export_db(path, block_height, **kwargs):

    global state_engine

    try:
        state_engine.export_db(path + (".%s" % block_height))
    except IOError, ie:
        if ie.errno == errno.ENOENT:
            log.error("No such file or directory: %s" + path)
            pass
        else:
            raise
