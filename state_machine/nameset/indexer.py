import json
import os
import traceback
from collections import defaultdict

import copy

import binascii
from utilitybelt import is_hex

import config
from virtualchain.bitcoin_blockchain import transactions


RESERVED_KEYS = [
   'virtualchain_opcode',
   'virtualchain_outputs',
   'virtualchain_senders',
   'virtualchain_block_number',
   'virtualchain_accepted',
   'virtualchain_txid',
   'virtualchain_txindex'
]


log = config.get_logger("indexer")

class StateEngine(object):
    def __init__(self, magic_bytes, opcodes, opfields, impl=None, state=None, initial_snapshots = {}, expected_snapshots={}, backup_frequency=None, backup_max_age=None, readonly=False):
        self.consensus_hashes = initial_snapshots
        self.pending_opts = defaultdict(list)
        self.magic_bytes = magic_bytes
        self.opcodes = opcodes[:]
        self.opfields = copy.deepcopy(opfields)
        self.state = state
        self.impl = impl
        self.lastblock = self.impl.get_first_block_id() - 1
        self.pool = None
        self.rejected = {}
        self.expected_snapshots = expected_snapshots
        self.backup_frequency = backup_frequency
        self.backup_max_age = backup_max_age
        self.readonly = readonly

        firsttime = True

        consensus_snapshots_filename = config.get_snapshots_filename(impl)
        lastblock_filename = config.get_lastblock_filename(impl)

        # check whether it is the first time
        for fp in [consensus_snapshots_filename, lastblock_filename]:
            if os.path.exists(fp):
                firsttime = False

        # Attempt to load the snapshots
        if os.path.exists(consensus_snapshots_filename):
            log.debug("Consensus snapshots at %s" % consensus_snapshots_filename)

            try:
                with open(consensus_snapshots_filename, "r") as f:
                    db_dict = json.loads(f.read())
                    assert 'snapshots' in db_dict
                    self.consensus_hashes = db_dict['snapshots']

            except Exception, e:
                log.error("FATAL: Failed to read consensus snapshots at %s" % (consensus_snapshots_filename))
                log.exception(e)
                os.abort()
        elif firsttime:
            log.debug("Consensus snapshots at %s" % consensus_snapshots_filename)

            try:
                with open(consensus_snapshots_filename, "w") as f:
                    f.write(json.dumps({'snapshots': self.consensus_hashes}))
                    f.flush()
            except Exception, e:
                log.error("FATAL: Failed to store initial consensus snapshot to %s" % consensus_snapshots_filename)
                log.exception(e)
                os.abort()
        else:
            log.error("No such file or directory: %s " % consensus_snapshots_filename)
            os.abort()

        # Process the last block
        if os.path.exists( lastblock_filename ):

            log.debug("Lastblock at %s" % lastblock_filename)

            self.lastblock = self.get_lastblock()
            log.debug("Last block: %s(%s) " % (self.lastblock, lastblock_filename))
            if self.lastblock is None:
                log.error("FATAL: Failed to read last block id at %s" % lastblock_filename)
                log.exception(e)
                os.abort()

        elif firsttime:
            log.debug("lastblock at %s" % lastblock_filename)

            try:
                with open(lastblock_filename, "w") as f:
                    f.write("%s" % self.lastblock)
                    f.flush()
            except Exception, e:
                log.error("FATAL: Failed to store initial last block(%s) to %s" % (self.lastblock, lastblock_filename))
                log.exception(e)
                os.abort()

        else:
            log.error("FATAL: No such file or directory exists: %s" % lastblock_filename)
            os.abort()

    def get_lastblock(self, lastblock_filename=None, impl=None):
        """
        Get the last block
        """
        if lastblock_filename is None:

            if impl is None:
                impl = self.impl

            lastblock_filename = config.get_lastblock_filename()

        if os.path.exists( lastblock_filename ):
            try:
                with open(lastblock_filename) as f:
                    lastblock_str = f.read().strip()
                    return int(lastblock_str)
            except Exception, e:
                log.error("Failed to read last block number at: %s" % lastblock_filename)
                return None
        return None


    def set_backup_frequency(self, backup_frequency):
        self.backup_frequency = backup_frequency

    def set_backup_max_age(self, backup_max_age):
        self.set_backup_max_age = backup_max_age

    @classmethod
    def build(cls, bitcoind_opts, end_block_id, state_engine, expected_snapshots={}, tx_filter=None):
        """
        Top-level call to process all blocks in the zonefilemanage
        Goes and fetch all OP_RETURN nulldata in order, and feeds them into the state-engine using db_parse, db_check, db_commit and db_save
        """
        first_block_id = state_engine.lastblock + 1
        if first_block_id >= end_block_id:
            log.info("Up-to-date (%s -> %s)" % (first_block_id, end_block_id))
            return True

        rc = True
        batch_size = config.BLOCK_BATCH_SIZE

        log.info("Sync virtualchain state from %s to %s " % (first_block_id, end_block_id ))

        for block_id in xrange(first_block_id, end_block_id, batch_size):

            if not rc:
                break

            last_block_id = min(block_id + batch_size, end_block_id)
            block_ids_and_txs = transactions.get_virtual_transactions(bitcoind_opts, first_block_id, last_block_id )
            if block_ids_and_txs is None:
                raise Exception("Failed to get virtual transactions %s to %s" % (block_id, block_id + last_block_id))

            # sort by block height
            block_ids_and_txs.sort()

            for processed_block_id, txs in block_ids_and_txs:

                if state_engine.get_consensus_at(processed_block_id) is not None:
                    raise Exception("Already processed block %s (%s)" % (processed_block_id, state_engine.get_consensus_at(processed_block_id)))

                ops = state_engine.parse_block( processed_block_id, txs)
                consensus_hash = state_engine.process_block(processed_block_id, ops, expected_snapshots=expected_snapshots)

                if consensus_hash is not None:
                    rc = False
                    log.debug("Stopped processing at block %s" % processed_block_id)
                    break

                log.debug("CONSENSUS(%s) :%s" % (processed_block_id, state_engine.get_consensus_at(processed_block_id)))

                # Sanity check if given

                expected_consensus_hash = state_engine.get_expected_consensus_at(processed_block_id)
                if expected_snapshots is not None:
                    if str(consensus_hash) != str(expected_consensus_hash):
                        rc = False
                        log.error("FATAL: Divergence detected at %s: %s != %s" % (processed_block_id, consensus_hash, expected_consensus_hash))
                        traceback.print_stack()
                        os.abort()
                if not rc:
                    break

            log.debug("Last block is %s" % state_engine.lastblock)

            return rc





    def get_expected_consensus_at(self, block_id):
        """
        Get the expected consensus hash at a given block
        """
        return self.expected_snapshots.get(str(block_id), None)




    def get_consensus_at(self, block_id):
        """
        Get the consensus hash at a given block
        """
        return self.consensus_hashes.get(str(block_id), None)


    def parse_transaction(self, block_id, tx):
        """
        Given a block ID and OP_RETURN transaction, try to parse it into a virtual chain operation
        """

        op_return_hex = tx['nulldata']
        inputs = tx['vin']
        outputs = tx['vout']
        senders = tx['senders']

        if not is_hex(op_return_hex):
            return None

        if len(op_return_hex) % 2 != 0:
            return None

        try:
            op_return_bin = binascii.unhexlify(op_return_hex)
        except Exception, e:
            log.error("Failed to parse transaction: %s (OP_RETUAN= %s)" % (tx, op_return_hex))
            raise e

        if not op_return_bin.startswith( self.magic_bytes ):
            return None
        op_code = op_return_bin[len(self.magic_bytes)]

        if op_code not in self.opcodes:
            return None

        op_payload = op_return_bin[len(self.magic_bytes) + 1:]

        op = self.impl.db_parse( block_id, tx['txid'], tx['txindex'], op_code, op_payload, senders, inputs, outputs, db_state=self.state )

        if op is None:
            return None

        op['virtualchain_opcode'] = op_code
        op['virtualchain_outputs'] = outputs
        op['virtualchain_senders'] = senders
        op['virtualchain_block_number'] = block_id
        op['virtualchain_accepted'] = False  # not yet accepted
        op['virtualchain_txid'] = tx['txid']
        op['virtualchain_txindex'] = tx['txindex']

        return op


    def parse_block(self, block_id, txs):
        """
        Given the sequence of transactions in a block, turn them into a sequence of virtual chain operations
        """

        ops = []

        for i in xrange(0, len(txs)):

            tx = tx[i]
            op = self.parse_transaction( block_id, tx )
            if op is not None:
                ops.append(op)

        return ops

    def remove_reserved_keys(self, op):

        sanitized = {}
        reserved = {}

        for k in op.keys():
            if str(k) not in RESERVED_KEYS:
                sanitized[str(k)] = copy.deepcopy(op[k])
            else:
                reserved[str(k)] = copy.deepcopy(op[k])

        return sanitized, reserved



    def process_ops(self, block_id, ops):
        """
        Given a transaction-orded sequence of parsed operations, check the validity and give them to the state engine to affect state changes.
        """
        new_ops = defaultdict(list)

        for op in self.opcodes:
            new_ops[op] = []

        new_ops['virtualchain_ordered'] = []
        new_ops['virtualchain_all_ops'] = op

        to_commit_sanitized = []
        to_commit_reserved = []

        # Let the implementation do an initial scan over the blocks
        initial_scan = []

        for i in xrange(0, len(ops)):
            op_data = ops[i]
            op_sanitized, _ = self.remove_reserved_keys(op_data)
            initial_scan.append(copy.deepcopy(op_sanitized))

        for i in xrange(0, len(ops)):
            op_data = ops[i]
            op_sanitized, op_reserved = self.remove_reserved_keys(op_data)

            opcode = op_reserved['virtualchain_opcode']

            # Check this op
            self.impl.db_check()







    def process_block(self, block_id, ops, backup=False, expected_snapshots=None):

        log.debug("Process block %s (%s virtual transactions)" % (block_id, len(ops)))

        if expected_snapshots is None:
            expected_snapshots = self.expected_snapshots

        new_ops = self.process_ops(block_id, ops)
        sanitized_ops = {}

        consensus_hash = self.snapshot(block_id, new_ops['virtualchain_ordered'])

        # Sanity check

        if expected_snapshots.has_key(block_id) and expected_snapshots[block_id] != consensus_hash:
            log.error("FATAL: Consensus hash mismatch at height %s: %s != %s" % (block_id, expected_snapshots[block_id], consensus_hash))
            traceback.print_stack()
            os.abort()

        for op in new_ops.keys():
            sanitized_ops[op] = []
            for i in xrange(0, len(new_ops[op])):

                op_sanitized, op_reserved = self.remove_reserved_keys(new_ops[op][i])
                sanitized_ops[op].append(op_sanitized)

        rc = self.save(block_id, consensus_hash, sanitized_ops, backup=backup)
        if not rc:
            log.debug("Early indexing termination at %s" % block_id)

            return None
        return consensus_hash










