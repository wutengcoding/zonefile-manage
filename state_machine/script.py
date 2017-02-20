import traceback
from config import get_logger
from state_machine.b40 import *
import virtualchain

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
