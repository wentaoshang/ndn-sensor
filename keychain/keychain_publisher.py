from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import Sha256WithRsaSignature
from pyndn.security import KeyType
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import SelfVerifyPolicyManager
from pyndn.util import Blob

import hashlib
from Crypto.PublicKey import RSA

import socket

import keychain_config

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('::1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, data):
        wire = data.wireEncode()
        self.sock.sendall(str(bytearray(wire.toBuffer())))

publisher = RepoSocketPublisher(12345)

def getKeyID(key):
    pub_der = key.publickey().exportKey(format="DER")
    return bytearray(hashlib.sha256(pub_der).digest())

identityStorage = MemoryIdentityStorage()
privateKeyStorage = MemoryPrivateKeyStorage()
keyChain = KeyChain(IdentityManager(identityStorage, privateKeyStorage), 
                    SelfVerifyPolicyManager(identityStorage))

# Load keys into keychain
for key_name in keychain_config.keyfiles:
    keyfile = keychain_config.keyfile_folder + keychain_config.keyfiles[key_name]
    f = open(keyfile, "r")
    key = RSA.importKey(f.read())
    name = Name(key_name).append(getKeyID(key))
    key_pub_der = bytearray(key.publickey().exportKey(format="DER"))
    key_pri_der = bytearray(key.exportKey(format="DER"))
    identityStorage.addKey(name, KeyType.RSA, Blob(key_pub_der))
    privateKeyStorage.setKeyPairForKeyName(name, key_pub_der, key_pri_der)

# Generate certificates
for pair in keychain_config.keychain:
    signee_name = pair[0]
    signer_name = pair[1]
    
    signee_keyfile = keychain_config.keyfile_folder + keychain_config.keyfiles[signee_name]
    signer_keyfile = keychain_config.keyfile_folder + keychain_config.keyfiles[signer_name]
    
    f = open(signee_keyfile, "r")
    signee_key = RSA.importKey(f.read())
    f = open(signer_keyfile, "r")
    signer_key = RSA.importKey(f.read())
    
    signee_name = Name(signee_name).append(getKeyID(signee_key))
    signer_name = Name(signer_name).append(getKeyID(signer_key))
    print signee_name.toUri()
    print signer_name.toUri()

    key_data = Data(signee_name)
    key_data.setContent(bytearray(signee_key.publickey().exportKey(format="DER")))
    key_data.getMetaInfo().setFreshnessPeriod(10000000000)

    signer_cert_name = signer_name.getSubName(0, signer_name.size() - 1).append(
      "KEY").append(signer_name[-1]).append("ID-CERT").append("0")
    keyChain.sign(key_data, signer_cert_name)
    
    publisher.put(key_data)

