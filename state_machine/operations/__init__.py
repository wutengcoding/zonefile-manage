import sys

import register
import update
import transfer
import revoke
import copy


from config import *

from register import make_transaction as make_tx_name_register, check_register as check_register


log = get_logger("operations.__init__")


SERIALIZE_FIELDS = {
    "NAME_REGISTER": register.FIELDS,
    "NAME_UPDATE": update.FIELDS,
    "NAME_TRANSFER": transfer.FIELDS,
    "NAME_REVOKE": revoke.FIELDS
}

# CHECK_METHODS = {
#     "NAME_REGISTER": check_register,
#     "NAME_UPDATE": check_update,
#     "NAME_TRANSFER": check_transfer,
#     "NAME_REVOKE": check_revoke,
# }
CHECK_METHODS = {
     "NAME_REGISTER": check_register
}


def op_check(state_engine, nameop, block_id, checked_ops):
    """
    Given the state engine, the current block, the list of pending
    operations processed so far, and the current operation, determine
    whether or not it should be accepted.

    The operation is allowed to change once, as a result of a check
    """

    global CHECK_METHODS, MUTATE_FIELDS

    count = 0
    while count < 3:

        count += 1

        nameop_clone = copy.deepcopy(nameop)
        opcode = None

        if 'opcode' not in nameop_clone.keys():
            op = nameop_clone.get('op', None)
            try:
                assert op is not None, "BUG: no op defined"
                opcode = op_get_opcode_name(op)
                assert opcode is not None, "BUG: op '%s' undefined" % op
            except Exception, e:
                log.exception(e)
                log.error("FATAL: BUG: no 'op' defined")
                sys.exit(1)

        else:
            opcode = nameop_clone['opcode']

        check_method = CHECK_METHODS.get(opcode, None)
        try:
            assert check_method is not None, "BUG: no check-method for '%s'" % opcode
        except Exception, e:
            log.exception(e)
            log.error("FATAL: BUG: no check-method for '%s'" % opcode)
            sys.exit(1)

        rc = check_method(state_engine, nameop_clone, block_id, checked_ops)
        if not rc:
            # rejected
            break

        # did the opcode change?
        # i.e. did the nameop get transformed into a different opcode?
        new_opcode = nameop_clone.get('opcode', None)
        if new_opcode is None or new_opcode == opcode:
            # we're done
            nameop.clear()
            nameop.update(nameop_clone)
            break

        else:
            # try again
            log.debug("Nameop re-interpreted from '%s' to '%s' (%s)" % (opcode, new_opcode, count))
            nameop['opcode'] = new_opcode
            continue

    try:
        assert count < 3, "opcode flipflop loop detected"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: BUG: flipflop loop")
        sys.exit(1)


    return rc

def op_get_mutate_fields( op_name ):
    """
    Get the names of the fields that will change
    when this operation gets applied to a record.
    """

    global MUTATE_FIELDS

    if op_name not in MUTATE_FIELDS.keys():
        raise Exception("No such operation '%s'" % op_name)

    fields = MUTATE_FIELDS[op_name][:]
    return fields

