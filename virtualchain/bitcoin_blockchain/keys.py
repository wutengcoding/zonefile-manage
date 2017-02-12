import pybitcoin
import bitcoin
import os

#whether using testnet/regtest or mainnet
if os.environ.get("ZONEFILEMANAGE_TESTNET", None) == "1":

    version_byte = 111
    multisig_version_byte = 196

    #using testnet keys
    class TestnetPublicKey(pybitcoin.BitcoinPublicKey):
        _version_byte = 111

    class TestnetPrivateKey(pybitcoin.BitcoinPrivateKey):
        _pubkeyhash_version_byte = 111

    BitcoinPrivateKey = TestnetPrivateKey
    BitcoinPublicKey = TestnetPublicKey


