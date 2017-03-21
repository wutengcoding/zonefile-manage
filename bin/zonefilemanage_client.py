import xmlrpclib
from config import *
# from bin.zonefilemanage_server import get_global_server

log = get_logger("zonefilemanage_client")


def vote_for_name(name, action, block_id, poll):
    hosts = get_other_ips()
    for h in hosts:
        vote_for_name_to_one(name, action, block_id, poll, h)
    return True

proxy_pool = {}

def vote_for_name_to_one(name, action, block_id, poll, ip):
    log.info("%s vote for name %s to ip: %s, the poll is %s in block: %s" % (get_my_ip(), name, ip, poll, block_id))

    s = get_proxy(ip)

    s.rpc_vote_for_name_action(name, action, block_id, poll)
    return True


def get_proxy(ip):
    url = 'http://%s:%s' % (ip, RPC_SERVER_PORT)
    if url not in proxy_pool.keys():
        s = xmlrpclib.ServerProxy(url)
        proxy_pool[url] = s
    else:
        s = proxy_pool[url]
    return s


def declare_block_owner(block_id, owner_ip):
    hosts = get_other_ips()
    log.info("other hosts is %s" % hosts)
    for h in hosts:
        s = get_proxy(h)
        s.rpc_declare_block_owner(block_id, owner_ip)
    return True


def get_name_action_status(name, action):
    s = xmlrpclib.ServerProxy('http://%s:%s' % ("localhost", RPC_SERVER_PORT))
    res = s.rpc_collect_vote(name, action)
    return res


def get_other_ips():
    all_hosts = get_p2p_hosts()
    hosts = deepcopy(all_hosts)
    hosts.remove(get_my_ip())
    return hosts