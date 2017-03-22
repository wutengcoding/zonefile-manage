import xmlrpclib
import time
RPC_SERVER_PORT = 16264
cnt = 0
s = xmlrpclib.ServerProxy('http://172.17.0.2:%s' % RPC_SERVER_PORT)
for i in range(0, 10):
    res = s.rpc_get_name('foo' + str(i))
    if res != None:
        cnt += 1
    print res
s = xmlrpclib.ServerProxy('http://172.17.0.3:%s' % RPC_SERVER_PORT)
for i in range(0, 10):
    res = s.rpc_get_name('bar' + str(i))
    if res != None:
        cnt += 1
    print res
s = xmlrpclib.ServerProxy('http://172.17.0.4:%s' % RPC_SERVER_PORT)
for i in range(0, 10):
    res = s.rpc_get_name('chr' + str(i))
    print res
    if res != None:
        cnt += 1

print '**************cnt = %s *************' % cnt