from state_machine.operations.register import tx_extract as extract_register
from state_machine.operations.update import tx_extract as extract_update
from state_machine.operations.revoke import tx_extract as extract_revoke
from state_machine.operations.transfer import tx_extract as extract_transfer




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



