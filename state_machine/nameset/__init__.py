NAMEREC_FIELDS = [
    'name',  # the name itself
    'value_hash',  # the hash of the name's associated profile
    'sender',  # the scriptPubKey hex that owns this name (identifies ownership)
    'sender_pubkey',  # (OPTIONAL) the public key
    'address',  # the address of the sender

    'block_number',  # the block number when this name record was created (preordered for the first time)
    'first_registered',  # the block number when this name was registered by the current owner
    'last_renewed',  # the block number when this name was renewed by the current owner
    'revoked',  # whether or not the name is revoked

    'op',  # byte sequence describing the last operation to affect this name
    'txid',  # the ID of the last transaction to affect this name
    'vtxindex',  # the index in the block of the transaction.
]