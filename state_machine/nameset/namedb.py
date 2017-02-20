import shutil

import indexer
from db import *
from config import *
from state_machine.operations import *


DISPOSITION_RO = "readonly"
DISPOSITION_RW = "readwrite"
log = get_logger("namedb")

class ZonefileManageDB(indexer.StateEngine):
    """
    State engine implementation for ZonefileManage
    """
    def __init__(self, db_filename, disposition, expected_snapshots={}):

        initial_snapshots = GENESIS_SNAPSHOT
        if not os.path.exists( db_filename ):
            log.info("Initialze database from '%s' " % db_filename)
        else:
            log.info("Connect to database '%s'" % db_filename )

        self.db = None

        zonefilemanage_impl = get_implementation()

        self.db_filename = db_filename
        if os.path.exists(db_filename):
            self.db = namedb_open( db_filename )
        else:
            self.db = namedb_create( db_filename )

        readonly = (disposition == DISPOSITION_RO)

        super(ZonefileManageDB, self).__init__( MAGIC_BYTES,
                                                OPCODES,
                                                ZonefileManageDB.make_opfields(),
                                                impl=zonefilemanage_impl,
                                                initial_snapshots=initial_snapshots,
                                                state=self,
                                                expected_snapshots=expected_snapshots,
                                                readonly=readonly)
        backup_frequency = 1008  # once a week; 10 minute block time
        backup_max_age = 12096  # 12 weeks
        self.set_backup_frequency(backup_frequency)
        self.set_backup_max_age(backup_max_age)

        # collision detection
        self.collisions = {}




    @classmethod
    def make_opfields(cls):
        """
        Calculate the virtualchain-required opfields dict.
        """
        opfields = {}
        for opname in SERIALIZE_FIELDS.keys():
            opcode = NAME_OPCODES[opname]
            opfields[opcode] = SERIALIZE_FIELDS[opname]

        return opfields


    def export_db(self, path):
        """
        Copy the database to the given path
        """
        if self.db is not None:
            self.db.commit()

        shutil.copyfile(self.get_db_path(), path)


    def get_db_path(self):
        return self.db_filename