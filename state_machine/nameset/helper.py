from state_machine.operations.register import tx_extract as extract_register
from state_machine.operations.update import tx_extract as extract_update
from state_machine.operations.revoke import tx_extract as extract_revoke
from state_machine.operations.transfer import tx_extract as extract_transfer
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

EXTRACT_METHODS = {
    "NAME_REGISTER": extract_register,
    "NAME_UPDATE": extract_update,
    "NAME_TRANSFER": extract_transfer,
    "NAME_REVOKE": extract_revoke
}

def op_extract( op_name, data, senders, inputs, outputs, block_id, vtxindex, txid):

    """
    Extract an operation from transaction data
    """
    global EXTRACT_METHODS

    if op_name not in EXTRACT_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = EXTRACT_METHODS[op_name]
    op_data = method( data, senders, inputs, outputs, block_id, vtxindex, txid)

    return op_data

