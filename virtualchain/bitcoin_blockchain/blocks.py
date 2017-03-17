import socket

import bitcoin
import pybitcoin
import requests
import simplejson
from decimal import *
from config import get_logger
import protocoin
from protocoin.clients import *
from protocoin.exceptions import *
from protocoin.serializers import *
from protocoin.fields import *
import bits
from keys import version_byte as VERSION_BYTE
from virtualchain.bitcoin_blockchain.spv import SPVClient


import binascii


log = get_logger("blocks")

class BlockchainDownloader( BitcoinBasicClient ):
    """
    Fetch all transactions from the blockchain over a given range
    """

    coin = None

    def __init__(self, bitcoin_opts, spv_headers_path, first_block_height, last_block_height, p2p_port=None, sock=None, tx_filter=None):
        """
        Before calling this, the headers must be synchronized
        """

        if VERSION_BYTE == 0:
            self.coin = "bitcoin"
            if p2p_port is None:
                p2p_port = 8333

        else:
            self.coin = "bitcoin_testnet"
            if p2p_port is None:
                p2p_port = 18333

        if not os.path.exists( spv_headers_path ):
            raise Exception("No such file or directory %s " % (spv_headers_path))

        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((bitcoin_opts['bitcoind_server'], p2p_port))
            except socket.error, e:
                log.error("Failed to connect to %s:%s" % (bitcoin_opts['bitcoind_server'], p2p_port))

        super(BlockchainDownloader, self).__init__(sock)

        self.bitcoind_opts = bitcoin_opts
        self.spv_header_path = spv_headers_path
        self.first_block_height = first_block_height
        self.last_block_height = last_block_height
        self.finished = False
        self.tx_filter = tx_filter

        self.blocks = {} # map height to block hash
        self.block_info = {} # map block hash to block data {'height': ..., 'header': ..., 'txns': ..., 'handled': False}
        self.sender_info = {} # map tx hash to {output_index: {'block_hash': ..., 'tx_index': ...}}
        self.num_txs_received = 0
        self.num_blocks_requested = last_block_height - first_block_height + 1
        self.num_blocks_received = 0

        for i in xrange(first_block_height, last_block_height+1):
            block_header = SPVClient.read_header(spv_headers_path, i)
            if block_header is None:
                continue

            self.blocks[i] = block_header['hash']
            self.block_info[block_header['hash']] = {
                'height': i,
                'header': block_header,
                'txns': None,
                'handled': False
            }

        log.debug("BlockDownloader: fetch block %s-%s" % (first_block_height, last_block_height))

    def begin(self):
        log.debug("handshake (version %s )" % PROTOCOL_VERSION)
        version = Version()
        version.services = 0
        self.send_message(version)

    def handle_version(self, message_header, message):
        """
        Handle the Version message, and send a VerAck message when it receives the Version message
        """
        log.debug("handle version message")
        verack = VerAck()
        log.debug("send VerAck")
        self.send_message(verack)
        self.verack = True

        start_block_height = sorted(self.blocks.keys())[0]
        if start_block_height < 1:
            start_block_height = 1

        #blocks  height to block hash
        block_hashes = []
        for height in sorted(self.blocks.keys()):
            block_hashes.append(int(self.blocks[height], 16))

        start_block_height = sorted(self.blocks.keys())[0]
        if len(self.blocks.keys()) <= 1:
            end_block_height = start_block_height
        else:
            end_block_height = sorted(self.blocks.keys())[1]

        log.debug("Send getdata for %s-%s (%064x-%064x)" % (start_block_height, end_block_height, block_hashes[0], block_hashes[-1]))

        # send off the getdata
        getdata = GetData()
        block_inv_vec = []
        for block_hash in block_hashes:
            block_inv = Inventory()
            block_inv.inv_type = INVENTORY_TYPE['MSG_BLOCK']
            block_inv.inv_hash = block_hash

            block_inv_vec.append(block_inv)

        getdata.inventory = block_inv_vec
        self.send_message(getdata)



    def handle_ping(self, message_header, message):
        """
        Handle the ping message and then answer with a Pong message
        """
        log.debug("Handle Ping")
        pong = Pong()
        pong.nonce = message.nonce
        log.debug("Send Pong")
        self.send_message(pong)


    def handle_inv(self, message_header, inv_packet):

        log.debug("Handle inv of %s item(s)" % len(inv_packet.inventory))

        reply_inv = []
        for inv_info in inv_packet.inventory:
            inv_hash = "%064x" % inv_info.inv_hash
            if inv_info.inv_type == INVENTORY_TYPE["MSG_BLOCK"]:
                # Only ask for the block if we need it
                if inv_hash in self.block_info.keys() and self.block_info[inv_hash]['handled']:
                    log.debug("Will request block %s" % inv_hash)
                    reply_inv.append( inv_info )

        if len(reply_inv) > 0:
            getdata = GetData()
            getdata.inventory = reply_inv
            log.debug("Send getdata message in reply to inv for %s item(s)" % len(reply_inv))
            self.send_message(getdata)

        else:
            if self.have_all_block_data():
                self.loop_exit()


    def handle_block(self, message_header, block):
        log.info("handle block message %s" % block)
        if self.have_all_block_data():
            self.loop_exit()
            return

        block_hash = block.calculate_hash()

        # Is it a solicited block
        if block_hash not in self.block_info.keys():
            log.error("Ignoring unsolicited block %s" % (block_hash))
            return

        header = self.block_info[block_hash]['header']
        height = self.block_info[block_hash]['height']

        # does the block's transaction hashes match the merkle root
        tx_hashes = [block.txns[i].calculate_hash() for i in  xrange(0, len(block.txns))]
        mr = pybitcoin.MerkleTree( tx_hashes ).root()

        if mr != header['merkle_root']:
            log.error("Merkle root %s (%s) mismatch: expected %s, got %s" % (block_hash, height, header['merkle_root'], mr))
            return

        nulldata_txs = []
        relindex = 0

        log.info("The initial txns format is %s " % block.txns)

        for txindex in xrange(0, len(block.txns)):

            txdata = self.parse_tx(block.txns[txindex], header, block_hash, txindex)
            has_nulldata = False
            nulldata_payload = None

            for outp in txdata['vout']:
                if outp['scriptPubkey']['type'] == 'nulldata':
                    has_nulldata = True
                    nulldata_payload = bitcoin.deserialize_script(outp['scriptPubkey']['hex'])[1]
                    if type(nulldata_payload)  not in [str, unicode]:
                        log.debug("Malformed nulldata format")
                        nulldata_payload = outp['scriptPubkey']['hex'][4:]

            if not has_nulldata:
                continue
            log.info('nulldata is %s ' % binascii.unhexlify(nulldata_payload))
            txdata['nulldata'] = nulldata_payload
            txdata['relindex'] = relindex

            relindex += 1
            nulldata_txs.append(txdata)

        self.block_info[block_hash]['txns'] = nulldata_txs
        self.block_info[block_hash]['num_txns'] = len(block.txns)
        self.block_info[block_hash]['num_senders'] = 0

        sender_txhashes = []
        for txn in self.block_info[block_hash]['txns']:
            for i in xrange(0, len(txn['vin'])):
                inp = txn['vin'][i]
                sender_txid = inp['txid']
                inp_sender_outp = inp['vout']

                if str(sender_txid) not in sender_txhashes:
                    sender_txhashes.append(str(sender_txid))

                sinfo = self.make_sender_info(block_hash, txn, i)

                if not self.sender_info.has_key(sender_txid):
                    self.sender_info[sender_txid] = {}

                self.sender_info[sender_txid][inp_sender_outp] = sinfo

        # update accounting
        self.num_blocks_received += 1
        self.block_info[block_hash]['handled'] = True

        log.debug("Request %s nulldata sender TXs" % len(sender_txhashes))

        if self.have_all_block_data():
            self.loop_exit()

        return









    def make_sender_info(self, block_hash, txn, i):
        """
        Make sender information bundle for a particular input of the nulldata transaction
        """
        inp = txn['vin'][i]

        ret = {
            'amount_in': 0,
            'scriptPubkey': None,
            'addresses': None,
            # for matching the input this sender funded
            "txindex": txn['txindex'],
            "relindex": txn['relindex'],
            "output_index": inp['vout'],
            "block_hash": block_hash,
            "relinput": i
        }

        return ret


    def loop_exit(self):
        """
        Stop the loop
        """
        self.finished = True
        self.close_stream()

    def run(self):

        self.begin()

        try:
            self.loop()
        except socket.error, e:
            if not self.finished:
                log.exception(e)
                return False
        return True
        # Fetch remaining sender transactions
        # try:
        #     self.fetch_sender_txs()
        # except Exception, e:
        #     log.exception(e)
        #     return False

        # try:
        #     self.block_data_sanity_checks()
        # except AssertionError, ae:
        #     log.exception(ae)
        #     return False
        #
        # return True


    def block_data_sanity_checks(self):
        """
        Verify that the data we received makes sense.
        Return True on success
        Raise on error
        """
        assert self.have_all_block_data(), "Still missing block data"
        assert self.num_txs_received == len(self.sender_info.keys()), "Num TXs received: %s; num TXs requested: %s" % (
        self.num_txs_received, len(self.sender_info.keys()))

        for (block_hash, block_info) in self.block_info.items():
            for tx in block_info['txns']:
                assert None not in tx['senders'], "Missing one or more senders in %s; dump follows\n%s" % (
                tx['txid'], simplejson.dumps(tx, indent=4, sort_keys=True))
                for i in xrange(0, len(tx['vin'])):
                    inp = tx['vin'][i]
                    sinfo = tx['senders'][i]

                    assert self.sender_info.has_key(sinfo['txid']), "Surreptitious sender tx %s" % sinfo['txid']
                    assert inp['vout'] == sinfo[
                        'nulldata_vin_outpoint'], "Mismatched sender/input index (%s: %s != %s); dump follows\n%s" % \
                                                  (sinfo['txid'], inp['vout'], sinfo['nulldata_vin_outpoint'],
                                                   simplejson.dumps(tx, indent=4, sort_keys=True))

        return True


    def fetch_txs_rpc(self, bitcoind_opts, txids):
        """
        Fetch the given list of transactions via JSON-RPC interface
        """
        headers = {'content-type': 'application-json'}
        reqs = []
        ret = {}

        for i in xrange(0, len(txids)):

            txid = txids[i]

            req = {'method': 'getrawtransaction', 'params': [txid, 0], 'jsonrpc': '2.0', 'id': i}
            reqs.append(req)

        proto = "http"

        if bitcoind_opts.has_key("bitcoind_use_https") and bitcoind_opts["bitcoind_use_https"]:
            proto = "https"

        server_url = "%s://%s:%s@%s:%s" % (proto, bitcoind_opts["bitcoind_user"], bitcoind_opts["bitcoind_passwd"], bitcoind_opts["bitcoind_server"], bitcoind_opts["bitcoind_port"])
        resp = requests.post(server_url, headers=headers, data=simplejson.dumps(reqs))

        # get response

        try:
            resp_json = resp.json()
            assert type(resp_json) in [list]
        except Exception, e:
            log.error("Failed to parse transactions")
            return None

        for resp in resp_json:
            assert 'result' in resp, "Missing result"

            txhex = resp['result']
            assert txhex is not None, "Invalid RPC response '%s' (for %s)" % (simplejson.dumps(resp), txids[resp['id']])

            try:

                tx_bin = txhex.decode('hex')
                assert tx_bin is not None

                tx_hash_bin = pybitcoin.bin_double_sha256(tx_bin)[::-1]
                assert tx_hash_bin

                tx_hash = tx_hash_bin.encode('hex')
                assert tx_hash is not None

            except Exception, e:
                log.error("Failed to calculate txid of %s " % txhex)

            # solicited transaction
            assert tx_hash in txids, "Unsolicited transaction %s" % tx_hash

            # unique
            if tx_hash in ret.keys():
                continue

            txn_serializer = TxSerializer()
            txn = txn_serializer.deserialize(StringIO(binascii.unhexlify(txhex)))

            ret[tx_hash] = (self)


    def get_block_info(self):
        """
        Get the retrieved block information
        """
        if not self.finished:
            raise Exception("Not finished downloading")

        ret = []
        for (block_hash, block_data) in self.block_info.items():
            ret.append((block_data['height'], block_data['txns']))

        return ret


    def parse_tx(self, txn, block_header, block_hash, txindex):
        """
        Given a transaction message and its index in the block, create a 'verbose' transaction structure
        """

        txn_serializer = TxSerializer()
        tx_bin = txn_serializer.serialize(txn)


        txdata = {
            "version": txn.version,
            "locktime": txn.lock_time,
            "hex": binascii.hexlify(tx_bin),
            "txid": txn.calculate_hash(),
            "size": len(tx_bin),
            "blockhash": block_hash,
            "blocktime": block_header.get("timestamp", 0),
            "vin": [],
            "vout": [],

            # non-standard for virtualchain
            "txindex": txindex,
            "reindex": None,
            "senders": None,
            "nulldata": None
        }

        for inp in txn.tx_in:
            input_info = self.parse_tx_input(inp)
            txdata['vin'].append(input_info)

        for i in xrange(0, len(txn.tx_out)):
            outp = txn.tx_out[i]
            output_info = self.parse_tx_output(i, outp)
            txdata['vout'].append(output_info)

        txdata['senders'] = [None] * len(txdata['vin'])

        return txdata

    def parse_tx_output(self, i, outp):
        """
        Given a tx output, turn it into an easy-to-read
        dict (i.e. like what bitcoind would give us).
        """
        scriptpubkey = binascii.hexlify(outp.pk_script)
        script_info = bits.tx_output_parse_scriptPubKey(scriptpubkey)
        return {
            "value": Decimal(outp.value) / Decimal(10 ** 8),
            "n": i,
            "scriptPubkey": script_info
        }



    def parse_tx_input(self, inp):
        scriptSig = binascii.hexlify(inp.signature_script)
        prev_txid = "%064x" % inp.previous_output.out_hash

        ret = {
            "vout": inp.previous_output.index,
            "txid": prev_txid,
            "scriptSig": {
                "hex": scriptSig,
                "asm": bits.tx_script_to_asm(scriptSig)
            }
        }
        return ret

    def fetch_sender_txs(self):
        """
        Fetch all sender txs via JSON-RPC and merge them into our block data
        """
        # fetch remaining sender transactions
        if len(self.sender_info.keys()) > 0:

            sender_txids = self.sender_info.keys()[:]
            sender_txid_batches = []
            batch_size = 20

            for i in xrange(0, len(sender_txids), batch_size):
                sender_txid_batches.append(sender_txids[i:i+batch_size])

            for i in xrange(0, len(sender_txid_batches)):

                sender_txids_batch = sender_txid_batches[i]
                log.debug("Fetch %s TXs via JSON-RPC (%s - %s of %s)" % (len(sender_txids_batch), i * batch_size, i * batch_size + len(sender_txids_batch), len(sender_txids)))

                sender_txs = None

                for j in xrange(0, 5):
                    sender_txs = self.fetch_txs_rpc(self.bitcoind_opts, sender_txids_batch)
                    if sender_txids is None:
                        log.error("Failed to fetch transactions; Trying again (%s of %s)" % (j+1, 5))
                        time.sleep(j+1)
                        continue
                    break

                if sender_txs is None:
                    raise Exception("Failed to fetch transactions")

                for sender_txid, sender_tx in sender_txs.items():

                    assert sender_txid in self.sender_info.keys(), "Unsolicited sender tx %s" % sender_txid

                    # match sender outputs to the nulldata tx's input
                    for nulldata_input_vout_index in self.sender_info[sender_txid].keys():
                        if sender_txid != "0000000000000000000000000000000000000000000000000000000000000000":

                            assert nulldata_input_vout_index < len(sender_tx['vout']), "Output index %s is out of bounds for %s" % (sender_txid)

                            # save sender info
                            self.add_sender_info( sender_txid, nulldata_input_vout_index, sender_tx['vout'][nulldata_input_vout_index])

                        else:
                            self.add_sender_info(sender_txid, nulldata_input_vout_index, sender_tx['vout'][0])

                    # Update accounting
                    self.num_txs_received += 1
        return True


    def have_all_block_data(self):
        """
        Whether we get the whole blocks
        """
        if not (self.num_blocks_received == self.num_blocks_requested):
            log.debug("Num blocks received: %s, num block requested: %s" % (self.num_blocks_received, self.num_blocks_requested))
            return False
        return True

    def add_sender_info(self, sender_txhash, nulldata_vin_outpoint, sender_out_data):
        """
        Record sender information in our block info
        """
        assert sender_txhash in self.sender_info.keys(), "Missing sender info for %s" % sender_txhash
        assert nulldata_vin_outpoint in self.sender_info[sender_txhash], "Missing outpoint %s for sender %s" % (
        nulldata_vin_outpoint, sender_txhash)

        block_hash = self.sender_info[sender_txhash][nulldata_vin_outpoint]['block_hash']
        relindex = self.sender_info[sender_txhash][nulldata_vin_outpoint]['relindex']
        relinput_index = self.sender_info[sender_txhash][nulldata_vin_outpoint]['relinput']

        value_in = sender_out_data['value']
        script_pubkey = sender_out_data['scriptPubKey']['hex']
        script_type = sender_out_data['scriptPubKey']['type']
        addresses = sender_out_data['scriptPubKey'].get("addresses", [])

        sender_info = {
            "amount": value_in,
            "script_pubkey": script_pubkey,
            "script_type": script_type,
            "addresses": addresses,
            "nulldata_vin_outpoint": nulldata_vin_outpoint,
            "txid": sender_txhash
        }

        # debit this tx's total value
        self.block_info[block_hash]['txns'][relindex]['fee'] += int(value_in * 10 ** 8)

        # remember this sender, but put it in the right place.
        # senders[i] must correspond to tx['vin'][i]
        self.block_info[block_hash]['txns'][relindex]['senders'][relinput_index] = sender_info

        return True
























