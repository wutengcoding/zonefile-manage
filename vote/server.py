import threading
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from config import get_logger, RPC_SERVER_PORT

log = get_logger("server")



class ZonefileManageRPCServer(threading.Thread, object):
    """
    RPC Server
    """
    def __init__(self, host='0.0.0.0', port=RPC_SERVER_PORT):
        super(ZonefileManageRPCServer, self).__init__()
        self.rpc_server = None
        self.host = host
        self.port = port

    def run(self):
        """
        Server until asked to stop
        """
        self.rpc_server = ZonefileManageRPC(self.host, self.port)
        self.rpc_server.serve_forever()

    def stop_server(self):
        """
        Stop serving
        """
        if self.rpc_server is not None:
            self.rpc_server.shutdown()

    def collect_vote_poll(self, name):
        return self.rpc_server.collect_vote(name)


class SimpleXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    rpc_path = ('/RPC2',)


class ZonefileManageRPC(SimpleXMLRPCServer):
    """
    ZonefileManage RPC server
    """
    def __init__(self, host='0.0.0.0', port = RPC_SERVER_PORT, handler = SimpleXMLRPCRequestHandler):
        SimpleXMLRPCServer.__init__(self,(host, port), handler, allow_none=True)
        log.info("ZonefileManageRPC listening on (%s, %s)" % (host, port))
        # Register method
        for attr in dir(self):
            if attr.startswith("rpc_"):
                method = getattr(self, attr)
                if callable(method) or hasattr(method, '__call__'):
                    self.register_function(method)
        # Initial the voteing result
        self.vote_poll = {}
        self.vote_count = {}

    def rpc_vote_for_name(self, name, poll):
        try:
            assert type(poll) is bool
        except Exception, e:
            log.exception(e)
        if name in self.vote_count.keys():
            self.vote_count[name] += 1
        else:
            self.vote_count[name] = 1

        if poll:
            if name in self.vote_poll.keys():
                self.vote_poll[name] += 1
            else:
                self.vote_poll[name] = 1

    def rpc_ping(self):
        return 'hello, world'

    def collect_vote(self, name):
        """
        Collect the vote result for a name
        """
        try:
            assert name in self.vote_poll.keys() and name in self.vote_count.keys(), "Collect for invalid name %s" % name
            return self.vote_poll[name] * 2 > self.vote_count[name]
        except Exception, e:
            log.exception(e)

if __name__ == '__main__':
    rpc_server = ZonefileManageRPCServer()
    rpc_server.start()