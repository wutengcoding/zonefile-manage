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
else:

    version_byte = 0
    multisig_version_byte = 5

    # using mainnet keys
    BitcoinPrivateKey = pybitcoin.BitcoinPrivateKey
    BitcoinPublicKey = pybitcoin.BitcoinPublicKey


def script_hex_address( script_hex ):
    """
    Examine a scriptPubkey and extract an address
    """
    if script_hex.startswith("76a914") and script_hex.endswith("88ac") and len(script_hex) == 50:
        # p2pkh script
        return pybitcoin.script_hex_to_address( script_hex, version_byte=version_byte )

    elif script_hex.startswith("a914") and script_hex.endswith("87") and len(script_hex) == 46:
        # p2sh script
        return bitcoin.script_to_address( script_hex, vbyte=multisig_version_byte )

    else:
        raise ValueError("Nonstandard script %s" % script_hex)




