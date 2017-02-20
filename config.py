import os
import logging
DEBUG = False
if os.environ.get("ZONEFILEMANAGE_DEBUG") == "1":
    DEBUG = True

REINDEX_FREQUENCY = 300 # seconds
if os.environ.get("ZONEFILEMANAGE_TEST") == "1":
    REINDEX_FREQUENCY = 1
FIRST_BLOCK_MAINNET = 373601

if os.environ.get("ZONEFILEMANAGE_TEST", None) is not None and os.environ.get("ZONEFILEMANAGE_TEST_FIRST_BLOCK", None) is not None:
    FIRST_BLOCK_MAINNET = int(os.environ.get("BLOCKSTACK_TEST_FIRST_BLOCK"))


GENESIS_SNAPSHOT = {
    str(FIRST_BLOCK_MAINNET-4): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-3): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-2): "17ac43c1d8549c3181b200f1bf97eb7d",
    str(FIRST_BLOCK_MAINNET-1): "17ac43c1d8549c3181b200f1bf97eb7d",
}


MAGIC_BYTES = 'rt'

# Opcodes
NAME_REGISTER = ':'
NAME_UPDATE = '+'
NAME_TRANSFER = '>'
NAME_REVOKE = '~'

OPCODES = [
    NAME_REGISTER,
    NAME_UPDATE,
    NAME_TRANSFER,
    NAME_REVOKE
]

NAME_OPCODES = {
    "NAME_REGISTER": NAME_REGISTER,
    "NAME_UPDATE": NAME_UPDATE,
    "NAME_TRANSFER": NAME_TRANSFER,
    "NAME_REVOKE": NAME_REVOKE
}

OPCODES_NAMES = {
    NAME_REGISTER: "NAME_REGISTER"
    # NAME_UPDATE: "NAME_UPDATE",
    # NAME_TRANSFER: "NAME_TRANSFER",
    # NAME_REVOKE: "NAME_REVOKE"
}

BLOCK_BATCH_SIZE = 10



NAMEREC_FIELDS = [
    'name',  # the name itself
    'value_hash',  # the hash of the name's associated profile
    'sender',  # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',  # (OPTIONAL) the public key
    'address',  # the address of the sender

    'block_number',  # the block number when this name record was created (preordered for the first time)
    'first_registered',  # the block number when this name was registered by the current owner
    'last_renewed',  # the block number when this name was renewed by the current owner
    'revoked',  # whether or not the name is revoked

    'op',  # byte sequence describing the last operation to affect this name
    'txid',  # the ID of the last transaction to affect this name
    'vtxindex',  # the index in the block of the transaction.
]



# op-return formats
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'fqn_min': 3,
    'fqn_max': 37,
    'name_hash': 16,
    'name_consensus_hash': 16,
    'value_hash': 20,
    'announce': 20,
    'max_op_length': 80
}


def get_logger(name="ZONEFILEMANAGE"):
    """
    Get virtualchain's logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel(level)
    console = logging.StreamHandler()
    console.setLevel(level)
    file_handler = logging.FileHandler("test.log")
    file_handler.setLevel(level)
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(
        os.getpid()) + '.%(thread)d) %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter(log_format)
    console.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)

    log.addHandler(console)
    log.addHandler(file_handler)
    return log


def get_virtualchain_name():
    return "zonefilemanage_server"



def get_snapshots_filename(impl=None):
    """
    Get the absolute path to the chain's consensus snapshots file
    """
    impl = get_impl(impl)

    working_dir = get_working_dir(impl)
    snapshots_filename = get_virtualchain_name() + ".snapshots"

    return os.path.join(working_dir, snapshots_filename)




def get_db_filename( impl=None ):
    """
    Get the absolute path to the last-block file
    """
    impl = get_impl(impl)
    db_filename = get_virtualchain_name() + ".db"
    working_dir = get_working_dir(impl=impl)

    return os.path.join(working_dir, db_filename)

def get_lastblock_filename(impl = None):
    """
    Get the absote path to the last-block file
    """
    impl = get_impl(impl)
    lastblock_filename = get_virtualchain_name() + ".lastblock"
    working_dir = get_working_dir(impl=impl)

    return os.path.join(working_dir, lastblock_filename)


def set_implementation( impl ):
    """
    The method should be called before anything else
    """

    global IMPL
    IMPL = impl

def get_implementation():
    global IMPL
    return IMPL


def get_impl(impl):
    """
    Get the implementation-- either the given or the globaly set
    """
    global IMPL
    if impl is not None:
        return impl
    elif IMPL is not None:
        return IMPL
    raise Exception("No virtualchain implmentation set")

def get_working_dir(impl = None):
    """
    Get the absolute path to the working directory
    """
    if os.environ.has_key("VIRTUALCHAIN_WORKING_DIR"):
        return os.environ["VIRTUALCHAIN_WORKING_DIR"]

    # impl = get_impl(impl)
    #
    # from os.path import expanduser
    # home = expanduser("~")
    #
    # working_dir = None
    # if hasattr(impl, "working_dir") and impl.working_dir is not None:
    #     working_dir = impl.working_dir
    #
    # else:
    #     working_dir = os.path.join(home, "." + impl.get_virtual_chain_name())
    #
    # if not os.path.exists(working_dir):
    #     os.makedirs(working_dir)
    #
    # return working_dir


def op_get_opcode_name(op_string):
    """
    Get the name of an opcode, given the operation's 'op' byte sequence
    """

    op = op_string[0]
    if op not in OPCODES_NAMES.keys():
        raise Exception("No such operation '%s'" % op)

    return OPCODES_NAMES['op']
