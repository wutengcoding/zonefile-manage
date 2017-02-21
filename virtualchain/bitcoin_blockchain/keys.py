import pybitcoin
import bitcoin
import os
import virtualchain

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





def address_reencode( address ):
    """
    Depending on whether or not we're in testnet
    or mainnet, re-encode an address accordingly.
    """
    vb = pybitcoin.b58check_version_byte( address )

    if os.environ.get("ZONEFILEMANAGE_TESTNET") == "1":
        if vb == 0 or vb == 111:
            # convert to testnet p2pkh
            vb = 111

        elif vb == 5 or vb == 196:
            # convert to testnet p2sh
            vb = 196

        else:
            raise ValueError("unrecognized address %s" % address)

    else:
        if vb == 0 or vb == 111:
            # convert to mainnet p2pkh
            vb = 0

        elif vb == 5 or vb == 196:
            # convert to mainnet p2sh
            vb = 5

        else:
            raise ValueError("unrecognized address %s" % address)

    return pybitcoin.b58check_encode( pybitcoin.b58check_decode(address), vb )



def make_payment_script( address ):
    """
    Make a pay-to-address script.
    * If the address is a pubkey hash, then make a p2pkh script.
    * If the address is a script hash, then make a p2sh script.
    """
    vb = pybitcoin.b58check_version_byte(address)

    if vb == version_byte:
        return pybitcoin.make_pay_to_address_script( address )

    elif vb == multisig_version_byte:
        return bitcoin.mk_scripthash_script( address )

    else:
        raise ValueError("Unrecognized address '%s'" % address )


def is_singlesig( privkey_info ):
    """
    Does the given private key info represent
    a single signature bundle? (i.e. one private key)?
    """
    if type(privkey_info) not in [str, unicode]:
        return False

    try:
        virtualchain.BitcoinPrivateKey(privkey_info)
        return True
    except:
        return False