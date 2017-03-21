import xmlrpclib
from config import *
# from bin.zonefilemanage_server import get_global_server

log = get_logger("zonefilemanage_client")


def vote_for_name(name, action, poll):
    all_hosts = get_p2p_hosts()
    hosts = deepcopy(all_hosts)
    hosts.remove(get_my_ip())
    for h in hosts:
        vote_for_name_to_one(name, action, poll, h)
    return True

def vote_for_name_to_one(name, action, poll, ip):
    log.info("%s vote for name %s to ip: %s" % (get_my_ip(), name, ip))
    s = xmlrpclib.ServerProxy('http://%s:%s' % (ip, RPC_SERVER_PORT))
    s.rpc_vote_for_name_action(name, action, poll)
    s('close')
    return True


def declare_block_owner(block_id, owner_ip):
    hosts = get_p2p_hosts()
    for h in hosts:
        s = xmlrpclib.ServerProxy('http://%s:%s' % (h, RPC_SERVER_PORT))
        log.info("Sending block owner message to %s" % h)
        s.rpc_declare_block_owner(block_id, owner_ip)
        s('close')
    return True


def get_name_action_status(name, action):
    s = xmlrpclib.ServerProxy('http://%s:%s' % ("0.0.0.0", RPC_SERVER_PORT))
    res = s.rpc_collect_vote(name, action)
    s('close')
    return res