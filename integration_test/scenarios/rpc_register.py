from integration_test.testlib import *

wallets = [
    #prvate key wif
    Wallet( "5JesPiN68qt44Hc2nT8qmyZ1JDwHebfoh9KQ52Lazb1m1LaKNj9", 100000000000 ),
    Wallet( "5KHqsiU9qa77frZb6hQy9ocV7Sus9RWJcQGYYBJJBb2Efj1o77e", 100000000000 ),
    Wallet( "5Kg5kJbQHvk1B64rJniEmgbD83FpZpbw2RjdAZEzTefs9ihN3Bz", 100000000000 ),
    Wallet( "5JuVsoS9NauksSkqEjbUZxWwgGDQbMwPsEfoRBSpLpgDX1RtLX7", 5500 ),
    Wallet( "5KEpiSRr1BrT8vRD7LKGCEmudokTh1iMHbiThMQpLdwBwhDJB1T", 5500 )
]
consensus = "17ac43c1d8549c3181b200f1bf97eb7d"

def scenario( wallets, **kw ):
    zonefilemanage_name_register('foo', wallets[1].addr, wallets[0].privkey)
    next_block(**kw)

    zonefilemanage_name_update('foo', '1'*20, wallets[0].privkey)
    next_block(**kw)
    print 'scenario successfully'

def check( state_engine ):
    print 'check successfully'