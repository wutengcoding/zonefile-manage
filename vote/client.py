import xmlrpclib
from config import get_p2p_vote_hosts, RPC_SERVER_PORT

def vote_for_name(name, poll):
    hosts = get_p2p_vote_hosts()
    for host in hosts:
        s = xmlrpclib.ServerProxy('http://%s:%s' % (host, RPC_SERVER_PORT))
        s.rpc_vote_for_name(name, poll)
        s.close()
