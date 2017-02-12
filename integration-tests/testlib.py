import virtualchain
from config import get_logger

log = get_logger("testlib")

class MultisigWallet(object):
    def __init__(self, m, *pks):

        self.privkey = virtualchain.make_multisig_info( m, pks )
        self.m = m
        self.n = len(pks)

        self.addr = self.privkey['address']

        log.info("Multisig wallet %s " % (self.addr))