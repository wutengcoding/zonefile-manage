import xmlrpclib
from config import get_p2p_hosts, RPC_SERVER_PORT

def vote_for_name(name, poll):
    hosts = get_p2p_hosts()
    for host in hosts:
        s = xmlrpclib.ServerProxy('http://%s:%s' % (host, RPC_SERVER_PORT))
        s.rpc_vote_for_name(name, poll)
        s.close()


def register(name):
    s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.34.154.228', RPC_SERVER_PORT))
    s.rpc_register_name(name)
    s.close()

if __name__ == '__main__':
    s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.11.126.50', RPC_SERVER_PORT))
    # s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.34.154.228', RPC_SERVER_PORT))
    # res = s.rpc_ping()
    # print res
    res = s.rpc_register_name('bar')
    print res