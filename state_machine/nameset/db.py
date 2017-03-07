import random
import sqlite3
import os
import traceback

from config import get_logger
import time
log = get_logger("db")


ZONEFILEMANAGE_DB_SCRIPT = ""
ZONEFILEMANAGE_DB_SCRIPT += """
CREATE TABLE name_records( name STRING NOT NULL,
                           name_hash128 TEXT NOT NULL,
                           value_hash TEXT,
                           sender TEXT NOT NULL,
                           sender_pubkey NOT NULL,
                           address TEXT,
                           block_number INT NOT NULL,
                           first_registered INT NOT NULL,
                           last_renewed INT NOT NULL,
                           op TEXT NOT NULL,
                           txid TEXT NOT NULL,
                           vtxindex INT NOT NULL,
                           consensus TEXT,
                           transfer_send_block_id INT,
                           --primary key includes block number, so an expired name can be re-registered
                           PRIMARY KEY(name, block_number)
                           );

"""
ZONEFILEMANAGE_DB_SCRIPT += """
CREATE TABLE ops_hashed( block_id INTEGER PRIMARY KEY NOT NULL,
                         ops_hash STRING NOT NULL);
"""


ZONEFILEMANAGE_DB_SCRIPT += """
CREATE INDEX hash_names_index ON name_records( name_hash128, name );
"""
ZONEFILEMANAGE_DB_SCRIPT += """
CREATE INDEX value_hash_names_index on name_records( value_hash, name );
"""
def namedb_open( path ):
    """
    Open a connection to the database
    """
    conn = sqlite3.connect( path, isolation_level=None, timeout=2**30 )
    conn.row_factory = namedb_row_factory

    return conn

def namedb_create( path ):
    """
    Create a sqlite3 db at the given path
    Create all tables and indexes we need
    """
    global ZONEFILEMANAGE_DB_SCRIPT

    if os.path.exists(path):
        raise Exception("Database '%s' already exists" % path)

    lines = [ l + ";" for l in ZONEFILEMANAGE_DB_SCRIPT.split(";")]
    conn = sqlite3.connect( path, isolation_level=None, timeout=2**30)

    for line in lines:
        conn.execute(line)

    conn.row_factory = namedb_row_factory

    return conn

def namedb_row_factory(cursor, row):
    pass


def namedb_query_execute(cur, query, values):
    """
    Execute a query.  If it fails, exit.

    DO NOT CALL THIS DIRECTLY.
    """

    timeout = 1.0
    while True:
        try:
            ret = cur.execute(query, values)
            return ret
        except sqlite3.OperationalError as oe:
            if oe.message == "database is locked":
                timeout = timeout * 2 + timeout * random.random()
                log.error(
                    "Query timed out due to lock; retrying in %s: %s" % (timeout, namedb_format_query(query, values)))
                time.sleep(timeout)

            else:
                log.exception(oe)
                log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
                log.error("\n".join(traceback.format_stack()))
                os.abort()

        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
            log.error("\n".join(traceback.format_stack()))
            os.abort()

def namedb_format_query( query, values ):
    """
    Turn a query into a string for printing.
    Useful for debugging.
    """

    return "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] )



def namedb_get_name(cur, name, current_block, included_expired=False, include_history=False):
    select_query = "SELECT * FROM name_records WHERE NAME = ?;"
    args = (name,)
    name_rows = namedb_query_execute(cur, select_query, args)
    name_row = name_rows.fetchone()

    if name_row is None:
        return None

    name_rec = {}
    name_rec.update(name_row)
    return name_rec

