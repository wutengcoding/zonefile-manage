import os
import logging
import importlib
import argparse
import random
import shutil
import socket
import time
import threading
import traceback
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer

os.environ['ZONEFILEMANAGE_DEBUG'] = '1'
os.environ['ZONEFILEMANAGE_TEST'] = '1'
# generate blocks to start our regtest
TEST_FIRST_BLOCK_HEIGHT = 250
os.environ['ZONEFILEMANAGE_TEST_FIRST_BLOCK'] = str(TEST_FIRST_BLOCK_HEIGHT + 6)
os.environ['ZONEFILEMANAGE_TESTNET'] = '1'
import sys
import os

TEST_RPC_PORT = 16264
TEST_CLIENT_RPC_PORT = 16286
ZONEFILEMANAGE_STORAGE_DRIVERS = "disk"

TEST_FIRST_BLOCK_HEIGHT = 250   # how many blocks we have to generate to start regtest


if os.environ.get("ZONEFILEMANAGE_STORAGE", None) is not None:
    ZONEFILEMANAGE_STORAGE_DRIVERS = os.environ.get("ZONEFILEMANAGE_STORAGE")

BITCOIN_DIR = "/tmp/bitcoin-regtest"
REINDEX_FREQUENCY = 5
# Hack around the absolute path
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from config import get_logger, get_working_dir, set_bitcoin_regtest_opts, get_p2p_hosts, get_previous_ips, RPC_SERVER_PORT
from blockchain.session import connect_bitcoind_impl
from blockchain.autoproxy import JSONRPCException
import virtualchain
from integration_test.testlib import *
from state_machine import nameset as state_engine

wallets = [
    #prvate key wif
    Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]

db_inst = None

log = get_logger("ZONEFILEMANAGE")

DEFAULT_SERVER_INI_TEMPLATE = """
[bitcoind]
passwd = blockstacksystem
server = localhost
port = 18332
p2p_port = 18444
use_https = False
user = blockstack
regtest = True
spv_path = @CLIENT_BLOCKCHAIN_HEADERS@

[blockstack]
server_version = 0.14.0
rpc_port = %s
backup_frequency = 3
backup_max_age = 30
blockchain_proxy = True
serve_zonefiles = True
serve_profiles = True
zonefiles = @ZONEFILES@
analytics_key = abcdef0123456789
zonefile_storage_drivers = disk
profile_storage_drivers = disk
atlas = True
atlas_seeds =
atlas_blacklist =
atlas_hostname = localhost
""" % TEST_RPC_PORT

DEFAULT_CLIENT_INI_TEMPLATE = """
[blockstack-client]
client_version = 0.14.0
server = localhost
port = %s
metadata = @CLIENT_METADATA@
storage_drivers = @CLIENT_STORAGE_DRIVERS@
storage_drivers_required_write = disk,blockstack-server
advanced_mode = true
api_endpoint_port = %s
rpc_token = a653b93e696a998f85f8fd2b241ff4dfcb5dd978fe1da26c413a4c2abf90321b
poll_interval = 1
queue_path = @CLIENT_QUEUE_PATH@
rpc_detach = True
blockchain_reader = bitcoind_utxo
blockchain_writer = bitcoind_utxo
anonymous_statistics = False
blockchain_headers = @CLIENT_BLOCKCHAIN_HEADERS@

[blockchain-reader]
utxo_provider = bitcoind_utxo
rpc_username = blockstack
rpc_password = blockstacksystem
server = localhost
port = 18332
use_https = False

[blockchain-writer]
utxo_provider = bitcoind_utxo
rpc_username = blockstack
rpc_password = blockstacksystem
server = localhost
port = 18332
use_https = False

[bitcoind]
passwd = blockstacksystem
server = localhost
port = 18332
use_https = False
user = blockstack
regtest = True
""" % (TEST_RPC_PORT, TEST_CLIENT_RPC_PORT)



class Pinger(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False

    def run(self):
        self.running = True
        bitcoind = bitcoin_regtest_connect(bitcoin_regtest_opts())
        while self.running:
            try:
                bitcoind.ping()
                time.sleep(0.25)
            except socket.error:
                bitcoind = bitcoin_regtest_connect(bitcoin_regtest_opts())

    def ask_join(self):
        self.running = False

def load_scenario( scenario_name ):
    """
    * a global variable 'wallet'
    * a global variable 'consensus'
    * a callable method 'scenario'
    * a callable method 'check'
    """
    log = get_logger("ZONEFILEMANAGE")
    log.debug("Load scenario %s " % sys.argv[1])
    # strip .py from scenario name
    if scenario_name.endswith(".py"):
        scenario_name = scenario_name[:-3]

    try:
        scenario = importlib.import_module(scenario_name)
    except ImportError, ie:
        raise Exception("Failed to import %s" % scenario_name)

    #validate
    if not hasattr(scenario, "wallets"):
        log.warning("Empty wallet for scenario '%s'" % scenario_name)
        scenario.wallets = {}

    if not hasattr(scenario, "consensus"):
        log.warning("No consensus hash for '%s'" % scenario_name)
        scenario.consensus = "00" * 16

    if not hasattr(scenario, "scenario"):
        log.error("Invalid scenario '%s': no 'scenario' method" % scenario_name)
        return None

    if not hasattr(scenario, "check"):
        log.error("Invalid scenario '%s': no 'check' method" % scenario_name)
        return None

    return scenario

def bitcoin_regtest_opts():
    return {
        "bitcoind_server": "127.0.0.1",
        "bitcoind_port": 18332,
        "bitcoind_p2p_port": 18444,
        "bitcoind_user": "wuteng",
        "bitcoind_passwd": "root",
        "bitcoind_use_https": False,
        "bitcoind_timeout": 60,
        "bitcoind_spv_path": os.path.join(os.environ.get("VIRTUALCHAIN_WORKING_DIR", None), "spv_header.dat")
    }


def bitcoind_regtest_reset():
    """
    Reset bitcoind regtest to a clean state
    """
    global BITCOIN_DIR

    bitcoin_dir = BITCOIN_DIR[:]
    bitcoin_pidpath = os.path.join(bitcoin_dir, "bitcoind.pid")
    bitcoin_conf = os.path.join(bitcoin_dir, "bitcoin.conf")

    opts = bitcoin_regtest_opts()
    set_bitcoin_regtest_opts(opts)

    if os.path.exists(bitcoin_dir):
        # if os.path.exists(bitcoin_pidpath):
            # kill running daemon
            # os.system("bitcoin-cli -regtest -conf=%s stop" % bitcoin_conf)
        for i in xrange(0, 10000000):
            rc = os.system("bitcoin-cli -regtest -conf=%s stop" % bitcoin_conf)
            if rc != 0:
                log.info("stop the bitcoind daemon")
                break
            else:
                delay = 2 ** i + (2**i)*random.random()
                try:
                    time.sleep(delay)
                except Exception, e:
                    log.exception(e)
        shutil.rmtree(bitcoin_dir)

    os.makedirs(bitcoin_dir)
    with open(bitcoin_conf, "w") as f:
        f.write("rpcuser=%s\nrpcpassword=%s\nregtest=1\ntxindex=1\nlisten=1\nserver=1\ndatadir=%s\ndebug=1" % (opts['bitcoind_user'], opts['bitcoind_passwd'], bitcoin_dir))
        # flush and fsync to force write
        f.flush()
        os.fsync(f.fileno())

    #start up
    log.debug("Starting up bitcoind in regtest mode")
    rc = os.system("bitcoind -daemon -conf=%s" % bitcoin_conf)
    if rc != 0:
        log.error("Failed to start 'bitcoind': rc = %s" % rc)
        return False

    while True:
        time.sleep(1.0)
        opts = bitcoin_regtest_opts()
        try:
            bitcoind = connect_bitcoind_impl( opts )
            bitcoind.getinfo()
            break
        except socket.error:
            pass
        except JSONRPCException:
            pass

    if is_main_worker():

        #generate 250 blocks and confirm them
        bitcoind = connect_bitcoind_impl( opts )

        res = bitcoind.generate(TEST_FIRST_BLOCK_HEIGHT - 1)
        if len(res) != TEST_FIRST_BLOCK_HEIGHT - 1:
            log.error("Did not generate %s blocks" % TEST_FIRST_BLOCK_HEIGHT - 1)
            return False
        log.info("bitcoind -regtest is ready")

    else:
        bitcoind = connect_bitcoind_impl(opts)
        p2p_port = 18444
        otherips = get_previous_ips()
        for ip in otherips:
            bitcoind.addnode("%s:%s" % (ip,p2p_port), 'onetry')
            log.debug("addnode for %s" % ip)



def bitcoion_regtest_fill_wallets( wallets, default_payment_wallet=None):
    """
    Given a set of wallets, make sure they each have 50 BTC
    """
    opts = bitcoin_regtest_opts()
    bitcoind = connect_bitcoind_impl( opts )

    for wallet in wallets:
        # fill each wallet
        fill_wallet(bitcoind, wallet, 50)
    if default_payment_wallet is not None:
        # fill optional default payment address
        fill_wallet(bitcoind, default_payment_wallet, 250)

    bitcoind.generate(6)

    print >> sys.stderr, ""
    for wallet in wallets + [default_payment_wallet]:
        if wallet is None:
            continue

        addr = get_wallet_addr( wallet )
        unspents = bitcoind.listunspent(0, 200000, [addr])

        SATOSHIS_PER_COIN = 10 ** 8
        value = sum([ int(round(s["amount"]*SATOSHIS_PER_COIN)) for s in unspents])

        print >> sys.stderr, "Address %s loaded with %s satoshis" % (addr, value)

    print >> sys.stderr, ""

    return True

def get_wallet_addr( wallet ):
    """
    Get a wallet's address
    """
    if type(wallet.privkey) in [str, unicode]:
        return virtualchain.BitcoinPublicKey(wallet.pubkey_hex).address()
    else:
        return wallet.addr

def fill_wallet( bitcoind, wallet, value):
    """
    Fill a test wallet on regtet bitcoind

    Return True on success
    Raise an error
    """
    if type(wallet.privkey) in [str, unicode]:
        #single private key
        testnet_wif = wallet.privkey
        if not testnet_wif.startswith("c"):
            testnet_wif = virtualchain.BitcoinPrivateKey(testnet_wif).to_wif()

        bitcoind.importprivkey(testnet_wif, "")

        addr = virtualchain.BitcoinPublicKey(wallet.pubkey_hex).address()
        log.info("Fill %s with %s " % (addr, value))
        bitcoind.sendtoaddress( addr, value)

    else:
        # multisig address
        testnet_wifs = []
        testnet_pubks = []
        for pk in wallet.privkey['private_keys']:
            if not pk.startswith("c"):
                pk = virtualchain.BitcoinPrivateKey(pk).to_wif()

            testnet_wifs.append(pk)
            testnet_pubks.append( virtualchain.BitcoinPrivateKey(pk).public_key().to_hex())

        multisig_info = virtualchain.make_multisig_info(wallet.m, testnet_wifs)
        bitcoind.addmultisigaddress( wallet.m, testnet_pubks)
        bitcoind.importaddress(multisig_info['address'])

        log.debug("Fill %s with %s" % (multisig_info['address'], value))
        bitcoind.sendtoaddress(multisig_info['address'], value)
    return True

def bitcoin_regtest_connect( opts, reset=False):
    """
    Create a connection to bitcoind -regtest
    """
    bitcoind = connect_bitcoind_impl( opts )
    return bitcoind



def bitcoin_regtest_next_block():
    """
    Get the blockchain height from the regtest daemon
    """

    opts = bitcoin_regtest_opts()
    bitcoind = bitcoin_regtest_connect(opts)
    bitcoind.generate(1)
    log.debug("Next block (now at %s)" % bitcoind.getblockcount())



def parse_args( argv ):
    """
    Parse argv to get the block time, scenario, working dir, etc
    """
    parser = argparse.ArgumentParser(description="Run a test scenario")
    parser.add_argument("--working_dir", type=str, help='Working directory to use to store database state', required = False)
    parser.add_argument("scenario_module", type=str, help="Python module to run")
    args, _  = parser.parse_known_args()
    return args




def run_zonefilemanage():


    working_dir = "/tmp/zonefilemanage"

    # errase prior state
    if os.path.exists(working_dir):
        log.debug("Remove %s " % working_dir)
        shutil.rmtree(working_dir)


    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    # export to test
    os.environ["VIRTUALCHAIN_WORKING_DIR"] = working_dir

    # set up bitcoind
    bitcoind_regtest_reset()

    virtualchain_working_dir = os.environ["VIRTUALCHAIN_WORKING_DIR"]

    spv_header_path = os.path.join(virtualchain_working_dir, "spv_headers.dat")
    virtualchain.setup_virtualchain(state_engine)

    # db = state_engine.get_db_state(disposition=state_engine.DISPOSITION_RW)

    log.info("Connect to the bitcoind ")

    # Start the pinger
    pinger = Pinger()
    pinger.start()

    bitcoind = bitcoin_regtest_connect(bitcoin_regtest_opts())

    if is_main_worker():
        log.info("fill up the default wallet")
        # set up the default payment wallet
        default_payment_wallet = MultisigWallet(2, '5JYAj69z2GuFAZHrkhRuBKoCmKh6GcPXgcw9pbH8e8J2pu2RU9z',
                                                        '5Kfg4xkZ1gGN5ozgDZ37Mn3EH9pXSuWZnQt1pzax4cLax8PetNs',
                                                        '5JXB7rNxZa8yQtpuKtwy1nWUUTgdDEYTDmaEqQvKKC8HCWs64bL')

        # load wallets
        bitcoion_regtest_fill_wallets(wallets, default_payment_wallet=default_payment_wallet)

    else:
        # Watch out for wallets
        for wallet in wallets:

            testnet_wif = wallet.privkey
            if not testnet_wif.startswith("c"):
                testnet_wif = virtualchain.BitcoinPrivateKey(testnet_wif).to_wif()

            bitcoind.importprivkey(testnet_wif, "")

            addr = virtualchain.BitcoinPublicKey(wallet.pubkey_hex).address()
            log.info("Watch out for %s" % (addr))

        for wallet in wallets:
            addr = get_wallet_addr(wallet)
            unspents = bitcoind.listunspent(0, 200000, [addr])

            SATOSHIS_PER_COIN = 10 ** 8
            value = sum([int(round(s["amount"] * SATOSHIS_PER_COIN)) for s in unspents])

            print >> sys.stderr, "Address %s loaded with %s satoshis" % (addr, value)



    db = state_engine.get_db_state(disposition=state_engine.DISPOSITION_RW)

    set_global_db(db)

    # Start up the rpc server
    server = ZonefileManageRPCServer(port = RPC_SERVER_PORT)
    server.start()

    while True:
        height = bitcoind.getblockcount()
        log.debug("Sync virtualchain up to %s " % height)
        virtualchain.sync_virtualchain(bitcoin_regtest_opts(), height, db)

        # wait for the next block
        deadline = time.time() + REINDEX_FREQUENCY
        while time.time() < deadline:
            try:
                time.sleep(1)
            except:
                break

def is_main_worker():
    import socket
    hostname = socket.gethostname()
    return hostname == 'ip-172-31-31-120' or hostname == 'ubuntu'


def set_global_db(inst):
    global db_inst
    if db_inst is None:
        db_inst = inst

def get_global_db():
    global db_inst
    return db_inst

class ZonefileManageRPCServer(threading.Thread, object):
    """
    RPC Server
    """
    def __init__(self, host='0.0.0.0', port=RPC_SERVER_PORT):
        super(ZonefileManageRPCServer, self).__init__()
        self.rpc_server = None
        self.host = host
        self.port = port

    def run(self):
        """
        Server until asked to stop
        """
        self.rpc_server = ZonefileManageRPC(self.host, self.port)
        self.rpc_server.serve_forever()

    def stop_server(self):
        """
        Stop serving
        """
        if self.rpc_server is not None:
            self.rpc_server.shutdown()

    def collect_vote_poll(self, name):
        return self.rpc_server.collect_vote(name)


class SimpleXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    rpc_path = ('/RPC2',)


class ZonefileManageRPC(SimpleXMLRPCServer):
    """
    ZonefileManage RPC server
    """
    def __init__(self, host='0.0.0.0', port = RPC_SERVER_PORT, handler = SimpleXMLRPCRequestHandler):
        SimpleXMLRPCServer.__init__(self,(host, port), handler, allow_none=True)
        log.info("ZonefileManageRPC listening on (%s, %s)" % (host, port))
        # Register method
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function(method)
        # Initial the voteing result
        self.vote_poll = {}
        self.vote_count = {}

    def rpc_vote_for_name(self, name, poll):
        try:
            assert type(poll) is bool
        except Exception, e:
            log.exception(e)
        if name in self.vote_count.keys():
            self.vote_count[name] += 1
        else:
            self.vote_count[name] = 1

        if poll:
            if name in self.vote_poll.keys():
                self.vote_poll[name] += 1
            else:
                self.vote_poll[name] = 1

    def rpc_register_name(self, name):
        """
        RPC method for register a name
        """

        log.info('Get the register rpc for %s' % name)
        resp = zonefilemanage_name_register(name, wallets[1].addr, wallets[0].privkey)
        return resp



    def rpc_get_name(self, name):

        db_inst = get_global_db()
        name_record = db_inst.get_name(name)
        return name_record

    def collect_vote(self, name):
        """
        Collect the vote result for a name
        """
        try:
            assert name in self.vote_poll.keys() and name in self.vote_count.keys(), "Collect for invalid name %s" % name
            return self.vote_poll[name] * 2 > self.vote_count[name]
        except Exception, e:
            log.exception(e)

if __name__ == '__main__':

    run_zonefilemanage()


