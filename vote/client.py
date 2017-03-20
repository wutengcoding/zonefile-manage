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
    # s = xmlrpclib.ServerProxy('http://%s:%s' % ('192.168.132.129', RPC_SERVER_PORT))



    s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.11.126.50', RPC_SERVER_PORT))
    # s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.88.127.158', RPC_SERVER_PORT))
    # s = xmlrpclib.ServerProxy('http://%s:%s' % ('52.34.154.228', RPC_SERVER_PORT))
    name = 'barfoo1'
    res = s.rpc_register_name(name)
    print res
    import time
    time.sleep(10)
    res = s.rpc_get_name(name)
    print res
