from config import get_logger
import virtualchain
import config
import os
import sys
log = get_logger("virtualchain_hooks")

DISPOSITION_RO = "readonly"
DISPOSITION_RW = 'readwrite'

def get_db_state( disposition = DISPOSITION_RO ):
    impl = config.get_implementation()
    if impl is None:
        impl = sys.modules[__name__]

    db_filename = config.get_db_filename(impl=impl)
    lastblock_filename = config.get_lastblock_filename()


    firstcheck = True
    for path in [db_filename, lastblock_filename]:
        if os.path.exists(path):
            # have already create the db
            firstcheck = False
    if not firstcheck and not os.path.exists(lastblock_filename):
        log.error("FATAL: no such file or directory: %s" % lastblock_filename)

    # verify that it is well-formed if it exists
    elif os.path.exists( lastblock_filename ):
        try:
            with open(lastblock_filename, "r") as f:
                int(f.read().strip())
        except Exception, e:
            log.error("FATAL: failed to parse: %s " % lastblock_filename)
            log.exception(e)
            os.abort()

    db_inst = ZonefileManageDB(db_filename, disposition)
