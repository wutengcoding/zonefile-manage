import os
from protocoin.serializers import *
from protocoin.clients import *
from protocoin.fields import *
import protocoin


from keys import version_byte as VERSION_BYTE

from config import get_logger

log = get_logger("spv")

GENESIS_BLOCK_HASH = None
GENESIS_BLOCK_MERKLE_ROOT = None
USE_MAINNET = False
USE_TESTNET = False
BLOCK_HEADER_SIZE = 80 + 1


GENESIS_BLOCK_HASH_MAINNET = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_BLOCK_MERKLE_ROOT_MAINNET = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

GENESIS_BLOCK_HASH_TESTNET = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
GENESIS_BLOCK_MERKLE_ROOT_TESTNET = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

if VERSION_BYTE == 0:
    log.debug("Using mainnet")
    USE_MAINNET = True
    GENESIS_BLOCK_HASH = GENESIS_BLOCK_HASH_MAINNET
    GENESIS_BLOCK_MERKLE_ROOT = GENESIS_BLOCK_MERKLE_ROOT_MAINNET

elif VERSION_BYTE == 111:
    log.debug("Using the testnet/regtest")
    USE_TESTNET = True
    GENESIS_BLOCK_HASH = GENESIS_BLOCK_HASH_TESTNET
    GENESIS_BLOCK_MERKLE_ROOT = GENESIS_BLOCK_MERKLE_ROOT_TESTNET



class BlockHash(SerializableMessage):
    def __init__(self):
        self.block_hash = None

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, "%064x" % self.block_hash)

class GetHeaders(SerializableMessage):
    """
    getheaders message
    """
    command = "getheaders"

    def __init__(self):
        self.version = PROTOCOL_VERSION
        self.block_hashes = []
        self.hash_stop = 0

    def add_block_hash(self, block_hash):
        if len(self.block_hashes) > 2000:
            raise Exception("A getheaders request can't have over 2000 block hashes")

        hash_num = int("0x" + block_hash, 16)
        bh = BlockHash()
        bh.block_hash = hash_num

        self.block_hashes.append(bh)
        self.hash_stop = hash_num

    def num_block_hashes(self):
        """
        Get the number of block header to request
        """
        return len(self.block_hashes)

    def __repr__(self):
        return "<%s block_hashes=[%s]>" % (self.__class__.__name__, ",".join([str(h) for h in self.block_hashes]))

class BlockHashSerializer( Serializer ):
    """
    Seriailization class for a BlockHash
    """
    model_class = BlockHash
    block_hash = Hash()

class GetHeadersSerializer( Serializer ):
    model_class = GetHeaders
    version = UInt32LEField()
    block_hashes = ListField(BlockHashSerializer)
    hash_stop = Hash()

protocoin.serializers.MESSAGE_MAPPING['getheaders'] = GetHeadersSerializer


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

    def hash_to_string(self, hash_int):
        return "%064x" % hash_int

    def handle_headers(self, message_header, block_header_message):
        log.debug("Handle headers (%s)" % len(block_header_message.headers))

        block_headers = block_header_message.headers

        serializer = BlockHeaderSerializer()
        current_height = SPVClient.height(self.path)
        if current_height is None:
            assert USE_TESTNET
            current_height = -1

        assert (current_height >= 0 and USE_MAINNET) or USE_TESTNET, "Invalid height %s" % current_height

        last_header = None

        if current_height >= 0:
            last_header = SPVClient.read_header(self.path, current_height)
            log.debug("Receive %s headers (%s to %s)" % (len(block_headers), current_height, current_height + len(block_headers)))

        else:
            log.debug("Receive %s testnet headers %s to %s " % (len(block_headers), current_height+1, current_height + len(block_headers)))
            last_header = {
                "version": block_headers[0].version,
                "prev_block_hash": "%064x" % block_headers[0].prev_block,
                "merkle_root": "%064x" % block_headers[0].merkle_root,
                "timestamp": block_headers[0].timestamp,
                "bits": block_headers[0].bits,
                "nonce": block_headers[0].nonce,
                "hash": block_headers[0].calculate_hash()
            }

        if (USE_MAINNET or USE_TESTNET and current_height >= 0) and last_header['hash'] != self.hash_to_string(block_headers[0].prev_block):
            raise Exception("Receive discontinuous block header at height %s: hash %s (expected %s )" % (\
                current_height, \
                self.hash_to_string(block_headers[0].prev_block),\
                last_header['hash']))

        header_start = 1
        if USE_TESTNET and current_height < 0:
            header_start = 0

        for i in xrange(header_start, len(block_headers)):
            prev_block_hash = self.hash_to_string(block_headers[i].prev_block)
            if i > 0 and prev_block_hash != block_headers[i-1].calculate_hash():
                raise Exception("Block '%s' is not continuous with block %s  ", prev_block_hash, block_headers[i-1].calculate_hash())

        if current_height < 0:
            # Save the first header
            if not os.path.exists(self.path):
                with open(self.path, "wb") as f:
                    block_header_serializer = BlockHeaderSerializer()
                    bin_data = block_header_serializer.serialize(block_headers[0])
                    f.write(bin_data)

            current_height = 0

        next_block_id = current_height + 1
        for block_header in block_headers:

            with open(self.path, "r+") as f:
                # Omit tx count
                block_header.txns_count = 0
                bin_data = serializer.serialize(block_header)

                if len(bin_data) != BLOCK_HEADER_SIZE:
                    raise Exception("Block %s(%s) has %s byte header" % (next_block_id, block_header.calculate_hash(), len(bin_data)))

                f.seek(BLOCK_HEADER_SIZE * next_block_id, os.SEEK_SET)
                f.write(bin_data)

                if SPVClient.height(self.path) > next_block_id:
                    break

                next_block_id += 1
        current_block_id = SPVClient.height(self.path)

        if current_block_id >= self.last_block_id - 1:
            # Get all the headers
            self.loop_exit()
            return
        prev_block_header = SPVClient.read_header(self.path, current_block_id)
        prev_block_hash = prev_block_header['hash']
        self.send_getheaders(prev_block_hash)







    def handle_ping(self, message_header, message):
        log.debug("Handle ping")
        pong = Pong()
        pong.nonce = message.nonce
        log.debug("Send pong")
        self.send_message(pong)


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

    def loop_exit(self):
        self.finished = True
        self.close_stream()

    def handle_version(self, message_header, message):

        log.debug("Handle version")
        verack = VerAck()
        log.debug("Send verack")
        self.send_message(verack)
        self.verack = True

        self.send_getheaders(self.first_block_hash)

    def send_getheaders(self, prev_block_hash):
        """
        Request block headers from a particular block hash
        """
        getheaders = GetHeaders()
        getheaders.add_block_hash(prev_block_hash)

        log.debug("Send getheaders")
        self.send_message(getheaders)


    def run(self):
        """
        Interact with the blockchain peer until we get a socket error or exit explicily
        """
        self.handshake()
        try:
            self.loop()
        except socket.error, se:
            if self.finished:
                return True
            else:
                raise


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
        else:
            return None

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
                log.info("Synchronize testnet %s to %s " % ( current_block_id+1, last_block_id ))

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
                bitcoind_port = int(p[1])

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
        return h


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

