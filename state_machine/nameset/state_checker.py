from config import get_logger
import sys
log = get_logger("state_checker")

def state_check_collisions(state_engine, nameop, history_id_key, block_id, checked_ops, collision_checker):
    # verify no collisions against already-accepted names
    collision_check = getattr(state_engine, collision_checker, None)
    try:
        assert collision_check is not None, "Collision-checker '%s' not defined" % collision_checker
        assert hasattr(collision_check, "__call__"), "Collision-checker '%s' is not callable" % collision_checker
        assert history_id_key in nameop.keys(), "History ID key '%s' not in name operation" % (history_id_key)
        assert 'op' in nameop.keys(), "BUG: no op in nameop"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: incorrect state_create() decorator")
        sys.exit(1)

    rc = collision_check(nameop[history_id_key], block_id, checked_ops)
    return rc

# # sanity check decorator for state-creating operations
def state_create(history_id_key, table_name, collision_checker):
    # handle function
    def wrap(check):
        # handle decorator args
        def wrapped_check(state_engine, nameop, block_id, checked_ops):
            rc = check(state_engine, nameop, block_id, checked_ops)

            # Verify no duplicates

            rc = state_check_collisions(state_engine, nameop, history_id_key, block_id, checked_ops, collision_checker)
            if rc:
                # this is a duplicate!
                log.debug("COLLISION on %s '%s'" % (history_id_key, nameop[history_id_key]))
                rc = False
            else:
                # no collision
                rc = True
            return rc
        return wrapped_check
    return wrap
