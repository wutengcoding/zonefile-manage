from state_machine.nameset import *
from state_machine.script import *
from state_machine.b40 import *
FIELDS = NUMEREC_FIELDS[:] + [
    'value_hash',
    'consensus_hash'
]





def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    sender_pubkey_hex = None

    try:

        # by construction, the first input comes from the principal
        # who sent the registration transaction...
        assert len(senders) > 0
        assert 'script_pubkey' in senders[0].keys()
        assert 'addresses' in senders[0].keys()

        sender_script = str(senders[0]['script_pubkey'])
        sender_address = str(senders[0]['addresses'][0])

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
        "sender": sender_script,
        "address": sender_address,
        "vtxindex": vtxindex,
        "txid": txid,
        "op": NAME_UPDATE
    }

    ret.update(parsed_payload)

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def parse(bin_payload):
    """
    Parse a payload to get back the name and update hash.
    NOTE: bin_payload excludes the leading three bytes.
    """

    if len(bin_payload) != LENGTHS['name_consensus_hash'] + LENGTHS['value_hash']:
        log.error("Invalid update length %s" % len(bin_payload))
        return None

    name_consensus_hash_bin = bin_payload[:LENGTHS['name_consensus_hash']]
    value_hash_bin = bin_payload[LENGTHS['name_consensus_hash']:]

    name_consensus_hash = hexlify(name_consensus_hash_bin)
    value_hash = hexlify(value_hash_bin)

    try:
        rc = update_sanity_test(None, name_consensus_hash, value_hash)
        if not rc:
            raise Exception("Invalid update data")
    except Exception, e:
        log.error("Invalid update data")
        return None

    return {
        'opcode': 'NAME_UPDATE',
        'name_consensus_hash': name_consensus_hash,
        'value_hash': value_hash
    }


def update_sanity_test(name, consensus_hash, data_hash):
    """
    Verify the validity of an update's data

    Return True if valid
    Raise exception if not
    """

    if name is not None and (not is_b40(name) or "+" in name or name.count(".") > 1):
        raise Exception("Name '%s' has non-base-38 characters" % name)

    if data_hash is not None and not is_hex(data_hash):
        raise Exception("Invalid hex string '%s': not hex" % (data_hash))

    if len(data_hash) != 2 * LENGTHS['value_hash']:
        raise Exception("Invalid hex string '%s': bad length" % (data_hash))

    return True

