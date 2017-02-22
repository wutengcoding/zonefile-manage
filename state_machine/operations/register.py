from state_machine.nameset import *
from state_machine.script import *
from state_machine.b40 import *
import virtualchain
from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, hex_hash160

from config import *

FIELDS = NAMEREC_FIELDS


def build(name):
    """
    Takes in the name that was preordered, including the namespace ID (but not the id: scheme)
    Returns a hex string representing up to the maximum-length name's bytes.

    Record format:

    0    2  3                             39
    |----|--|-----------------------------|
    magic op   name.ns_id (37 bytes)

    """

    readable_script = "NAME_REGISTRATION 0x%s" % (hexlify(name))
    hex_script = blockstack_script_to_hex(readable_script)
    packaged_script = add_magic_bytes(hex_script)

    return packaged_script


def get_registration_recipient_from_outputs( outputs ):

    ret = None

    for output in outputs:

        output_script = output['scriptPubkey']
        output_asm = output_script.get('asm')
        output_hex = output_script.get('hex')

        output_address = output_script.get('address')

        if output_asm[0:9] != 'OP_RETURN' and output_hex is not None:
            ret = output_hex
            break
    if ret is None:
        raise Exception("No registration address found")

    return ret

def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid):
    """
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script
    recipient:  the script_pubkey (as a hex string) of the principal that is meant to receive the name
    recipient_address:  the address from the recipient script
    """
    try:
        recipient = get_registration_recipient_from_outputs( outputs )
        recipient_address = virtualchain.script_hex_address(recipient)

        assert recipient is not None
        assert recipient_address is not None

        assert len(senders) > 0
        assert 'script_pubkey' in senders[0].keys()
        assert 'addresses' in senders[0].keys()

        sender_script = str(senders[0]['script_pubkey'])
        sender_address = str(senders[0]['address'][0])

        assert sender_script is not None
        assert sender_address is not None

        if str(senders[0]['script_type']) == 'pubkeyhash':
            sender_pubkey_hex = get_public_key_hex_from_tx(inputs, sender_address)
    except Exception, e:
        log.exception(e)
        raise Exception("Failed to extract")

    parsed_payload = parse(payload)
    assert parsed_payload is not None

    ret = {
        "value_hash": None,
        "sender": sender_script,
        "address": sender_address,
        "recipient": recipient,
        "recipient_address": recipient_address,
        "revoked": False,
        "last_renewed": block_id,
        "vtxindex": vtxindex,
        "txid": txid,
        "first_registered": block_id,  # NOTE: will get deleted if this is a renew
        "last_renewed": block_id,  # NOTE: will get deleted if this is a renew
        "op": NAME_REGISTER
    }

    ret.update(parsed_payload)

    # NOTE: will get deleted if this is a renew
    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse(bin_payload):
    """
    Interpret a block's nulldata back into a name.  The first three bytes (2 magic + 1 opcode)
    will not be present in bin_payload.

    The name will be directly represented by the bytes given.
    """

    fqn = bin_payload

    if not is_name_valid(fqn):
        return None

    return {
        'opcode': 'NAME_REGISTRATION',
        'name': fqn
    }




def make_transaction(name, register_addr, consensus_hash, payment_addr, zonefilemanage_client):
    script_pubkey = virtualchain.make_payment_script(payment_addr)
    nulldata = build(name)

    # Get inputs and from address
    inputs = tx_get_unspents(payment_addr, zonefilemanage_client)

    # Build custom outputs
    outputs = make_outputs(nulldata, inputs, payment_addr)

    return (inputs, outputs)


def make_outputs(data, inputs, payment_addr):
    return [
        {'script_hex': make_op_return_script(str(data), format='hex'),
         'value': 0}
    ]