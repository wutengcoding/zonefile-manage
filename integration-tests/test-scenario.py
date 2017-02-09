import os
import logging
import importlib
import argparse
import shutil
import time
os.environ['ZONEFILEMANAGE_DEBUG'] = '1'
os.environ['ZONEFILEMAMAGE_TEST'] = '1'

TEST_FIRST_BLOCK_HEIGHT = 250
os.environ['ZONEFILEMANAGE_TEST_FIRST_BLOCK'] = str(TEST_FIRST_BLOCK_HEIGHT + 6)

import sys
import os

TEST_RPC_PORT = 16264
TEST_CLIENT_RPC_PORT = 16286
ZONEFILEMANAGE_STORAGE_DRIVERS = "disk"

if os.environ.get("ZONEFILEMANAGE_STORAGE", None) is not None:
    ZONEFILEMANAGE_STORAGE_DRIVERS = os.environ.get("ZONEFILEMANAGE_STORAGE")

BITCOIN_DIR = "/tmp/bitcoin-regtest"

# Hack around the absolute path
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)


from config import DEBUG, get_logger
from blockchain.session import connect_bitcoind_impl
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
        "bitcoind_server": "localhost",
        "bitcoind_port": 18332,
        "bitcoind_p2p_port": 18444,
        "bitcoind_user": "wuteng",
        "bitcoind_passwd": "root",
        "bitcoind_use_https": False,
        "bitcoind_timeout": 60
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

    if os.path.exists(bitcoin_dir):
        if os.path.exists(bitcoin_pidpath):
            # kill running daemon
            os.system("bitcoin-cli -regtest -conf=%s stop" % bitcoin_conf)
            while True:
                rc = os.system("bitcoin-cli -regtest -conf=%s stop" % bitcoin_conf)
                if rc != 0:
                    break
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
        bitcoind = connect_bitcoind_impl( opts )
        bitcoind.getinfo()




def parse_args( argv ):
    """
    Parse argv to get the block time, scenario, working dir, etc
    """
    parser = argparse.ArgumentParser(description="Run a test scenario")
    parser.add_argument("--working_dir", type=str, help='Working directory to use to store database state', required = False)
    parser.add_argument("scenario_module", type=str, help="Python module to run")
    args, _  = parser.parse_known_args()
    return args

if __name__ == '__main__':
    print __file__
    print sys.argv
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: [scenario_module]"
        sys.exit(1)

    args = parse_args(sys.argv)

    print args
    interactive = False
    blocktime = 10
    working_dir = None
    scenario_module = args.scenario_module

    if hasattr(args, "blocktime") and args.blocktime is not None:
        interactive = True
        blocktime = args.blocktime

    if hasattr(args, "working_dir") and args.working_dir is not None:
        working_dir = args.working_dir

    else:
        working_dir = "/tmp/zonefilemanage-run-scenario.%s" % scenario_module

        # errase prior state
        if os.path.exists(working_dir):
            log.debug("Remove %s " % working_dir)
            shutil.rmtree(working_dir)

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    #load up the scenario
    scenario = load_scenario( scenario_module )
    """if scenario is None:
        print "Failed to load '%s'" % sys.argv[1]
        sys.exit(1)
    """
    #set up bitcoind
    bitcoind_regtest_reset()


