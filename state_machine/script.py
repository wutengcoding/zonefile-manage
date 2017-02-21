import traceback
from config import get_logger, TX_MIN_CONFIRMATIONS
from state_machine.b40 import *
import virtualchain
import pybitcoin
from pybitcoin.transactions import *
log = get_logger("script")


def is_name_valid(fqn):
    """
    Is a fully-qualified name acceptable?
    Return True if so
    Return False if not

    TODO: DRY up; use client
    """

    if fqn.count(".") != 1:
        return False

    name, namespace_id = fqn.split(".")

    if len(name) == 0 or len(namespace_id) == 0:
        return False

    if not is_b40(name) or "+" in name or "." in name:
        return False

    return True


def get_public_key_hex_from_tx(inputs, address):
    """
    Given a list of inputs and the address of one of the inputs,
    find the public key.

    This only works for p2pkh scripts.
    """

    ret = None

    for inp in inputs:

        input_scriptsig = inp.get('scriptSig', None)
        if input_scriptsig is None:
            continue

        input_asm = input_scriptsig.get("asm")

        if len(input_asm.split(" ")) >= 2:

            # public key is the second hex string.  verify it matches the address
            pubkey_hex = input_asm.split(" ")[1]
            pubkey = None

            try:
                pubkey = virtualchain.BitcoinPublicKey(str(pubkey_hex))
            except Exception, e:
                traceback.print_exc()
                log.warning("Invalid public key '%s'" % pubkey_hex)
                continue

            if address != pubkey.address():
                continue

            ret = pubkey_hex
            break

    return ret


def tx_get_unspents(address, utxo_client, min_confirmations=TX_MIN_CONFIRMATIONS):
    """
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs on success
    Raise UTXOException on error
    """

    min_confirmations = 1
    data = pybitcoin.get_unspents(address, utxo_client)

    try:
        assert type(data) == list, "No UTXO list returned"
        for d in data:
            assert isinstance(d, dict), 'Invalid UTXO information returned'
            assert 'value' in d, 'Missing value in UTXOs from {}'.format(address)

    except AssertionError, ae:
        log.exception(ae)
        raise

    # filter minimum confirmations
    return [d for d in data if d.get('confirmations', 0) >= min_confirmations]




def tx_sign_all_unsigned_inputs(private_key_info, unsigned_tx_hex):
    """
    Sign all unsigned inputs in the given transaction.

    @private_key_info: either a hex private key, or a dict with 'private_keys' and 'redeem_script'
    defined as keys.
    @unsigned_hex_tx: hex transaction with unsigned inputs

    Returns: signed hex transaction
    """
    inputs, outputs, locktime, version = pybitcoin.deserialize_transaction(unsigned_tx_hex)
    tx_hex = unsigned_tx_hex
    for i, input in enumerate(inputs):
        if input['script_sig']:
            continue

        # tx with index i signed with privkey
        tx_hex = tx_sign_input(str(unsigned_tx_hex), i, private_key_info)
        unsigned_tx_hex = tx_hex

    return tx_hex


def tx_sign_input(blockstack_tx, idx, private_key_info, hashcode=bitcoin.SIGHASH_ALL):
    """
    Sign a particular input in the given transaction.
    @private_key_info can either be a private key, or it can be a dict with 'redeem_script' and 'private_keys' defined
    """
    if is_singlesig(private_key_info):
        # single private key
        return tx_sign_singlesig(blockstack_tx, idx, private_key_info, hashcode=hashcode)

    elif is_multisig(private_key_info):

        redeem_script = private_key_info['redeem_script']
        private_keys = private_key_info['private_keys']

        redeem_script = str(redeem_script)

        # multisig
        return tx_sign_multisig(blockstack_tx, idx, redeem_script, private_keys, hashcode=bitcoin.SIGHASH_ALL)

    else:
        raise ValueError("Invalid private key info")