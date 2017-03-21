import xmlrpclib
from config import *


log = get_logger("zonefilemanage_client")


def vote_for_name(name, action, poll):
    hosts = get_p2p_hosts()
    for h in hosts:
        vote_for_name_to_one(name, action, poll, h)

def vote_for_name_to_one(name, action, poll, ip):
    s = xmlrpclib.ServerProxy('http://%s:%s' % (ip, RPC_SERVER_PORT))
    s.rpc_vote_for_name_action(name, action, poll)
    s('close')


def declare_block_owner(block_id, owner_ip):
    hosts = get_p2p_hosts()
    for h in hosts:
        s = xmlrpclib.ServerProxy('http://%s:%s' % (h, RPC_SERVER_PORT))
        log.info("Sending block owner message to %s" % h)
        s.rpc_declare_block_owner(block_id, owner_ip)
        s('close')


def get_name_action_status(name, action):
    status = False
    try:
        s = xmlrpclib.ServerProxy('http://%s:%s' % ("0.0.0.0", RPC_SERVER_PORT))
        status = s.rpc_collect_vote(name + "_" + action)
        s('close')
    except Exception, e:
        log.exception(e)
        return status
    return status