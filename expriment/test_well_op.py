import xmlrpclib
import time
import random
RPC_SERVER_PORT = 16264
cnt = 0
node1 = xmlrpclib.ServerProxy('http://172.17.0.2:%s' % RPC_SERVER_PORT)
node2 = xmlrpclib.ServerProxy('http://172.17.0.3:%s' % RPC_SERVER_PORT)
node3 = xmlrpclib.ServerProxy('http://172.17.0.4:%s' % RPC_SERVER_PORT)

proxy = [node1, node2, node3]

def generate_name_set():
    name_list = []
    for i in range(0, 100):
        name_list.append('bar' + str(i))

namelist = generate_name_set()

# do register name
for name in namelist:
    node_index = random.randint(0, 2)
    proxy = proxy[node_index]
    proxy.rpc_register_name(name)
    time.sleep(2)
# flush
node2.rpc_register_name('flush')

# do count successful name register
for name in namelist:
    result = node2.rpc_get_name(name)
    if result is not None:
        cnt += 1

print '*********************cnt = %s ********************' % cnt

