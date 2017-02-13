import virtualchain
import keylib
from config import get_logger

log = get_logger("testlib")


def test():
    print 'test'
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