import os
from protocoin.serializers import *
from protocoin.clients import *
from protocoin.fields import *
from keys import version_byte as VERSION_BYTE

from config import get_logger

log = get_logger("spv")

GENESIS_BLOCK_MERKLE_ROOT = None
USE_MAINNET = False
USE_TESTNET = False
BLOCK_HEADER_SIZE = 80 + 1

GENESIS_BLOCK_HASH_TESTNET = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
GENESIS_BLOCK_MERKLE_ROOT_TESTNET = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

class BlockHeaderClient( BitcoinBasicClient ):
    """
    Client to fetch and store block headers
    """

    coin = None
    def __init__(self, socket, headers_path, first_block_hash, last_block_id ):

        if VERSION_BYTE == 0:
            self.coin = "bitcoin"
        else:
            self.coin = "bitcoin_testnet"
        super(BlockHeaderClient, self).__init__(socket)
        self.path = headers_path
        self.last_block_id = last_block_id
        self.finished = False
        self.verack = False
        self.first_block_hash = first_block_hash

    def handshake(self):
        """
        This method implement the handshake of the Bitcoin protocol,
        it will send the Version message, and block until it receives a VerAck
        """
        log.debug("handshake (version %s)" % PROTOCOL_VERSION)
        version = Version()
        version.services = 0
        log.debug("send Version")
        self.send_message(version)


    def run(self):
        """
        Interact with the blockchain peer until we get a socket error or exit explicily
        """
        self.handshake()


class SPVClient(object):
    """
    Simplified Payment Verification client.
    """
    def __init__(self, path):
        SPVClient.init(path)

    @classmethod
    def init(cls, path):
        if not os.path.exists( path ):

            block_header_serializer = BlockHeaderSerializer()
            genesis_block_header = BlockHeader()

            if USE_MAINNET:
                # we know the mainnet block header
                # but we don't know the testnet/regtest block header
                genesis_block_header.version = 1
                genesis_block_header.prev_block = 0
                genesis_block_header.merkle_root = int(GENESIS_BLOCK_MERKLE_ROOT, 16)
                genesis_block_header.timestamp = 1231006505
                genesis_block_header.bits = int("1d00ffff", 16)
                genesis_block_header.nonce = 2083236893
                genesis_block_header.txns_count = 0

                with open(path, "wb") as f:
                    bin_data = block_header_serializer.serialize(genesis_block_header)
                    f.write(bin_data)

    @classmethod
    def height(cls, path):
        """
        Get the locally-stored block height
        """
        if os.path.exists( path ):
            sb = os.stat( path )
            h = (sb.st_size / BLOCK_HEADER_SIZE) - 1
            return h

    @classmethod
    def sync_header_chain(cls, path, bitcoind_server, last_block_id):
        """
        Synchronize our local block headers up to the last block Id given
        """
        current_block_id = SPVClient.height( path )
        if current_block_id is None:
            assert USE_TESTNET
            current_block_id = -1

        assert (current_block_id >= 0 and USE_MAINNET) or USE_TESTNET

        if current_block_id < last_block_id:
            if USE_MAINNET:
                log.info("Synchronize %s to %s " % ( current_block_id, last_block_id ))
            else:
                log.info("Synchronize testnet %s to %s " % ( current_block_id, last_block_id ))

            # need to sync
            if current_block_id >= 0:
                pass
            else:
                prev_block_hash = GENESIS_BLOCK_HASH_TESTNET

            # connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            bitcoind_port = 8333
            if ":" in bitcoind_server:
                p = bitcoind_server.split(":")
                bitcoind_server = p[0]
                bitcoind_port = p[1]

            log.info("connect to %s: %s" % (bitcoind_server, bitcoind_port))
            sock.connect((bitcoind_server, bitcoind_port))

            client = BlockHeaderClient(sock, path, prev_block_hash, last_block_id)

            # get headers
            client.run()


    @classmethod
    def read_header_at(cls, f):
        """
        Given an open file-like object, read a block header from it and return it as a dict containing :
        """
        header_parser = BlockHeaderSerializer()
        hdr = header_parser.deserialize(f)
        h = {}
        h['version'] = hdr.version
        h['prev_block_hash'] = "%064x" % hdr.prev_block
        h['merkle_root'] = "%064x" % hdr.merkle_root
        h['timestamp'] = hdr.timestamp
        h['bits'] = hdr.bits
        h['nonce'] = hdr.nonce
        h['hash'] = hdr.calculate_hash()



    @classmethod
    def read_header(cls, headers_path, block_height):
        """
        Get a block header at a particular height from disk
        """
        if os.path.exists(headers_path):
            header_parser = BlockHeaderSerializer()
            sb = os.stat(headers_path)
            if sb.st_size < BLOCK_HEADER_SIZE * block_height:
                return None

            with open(headers_path, "rb") as f:
                f.seek(block_height * BLOCK_HEADER_SIZE, os.SEEK_SET)
                hdr = SPVClient.read_header_at(f)
            return hdr
        else:
            return None

