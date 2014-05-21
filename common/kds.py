from pyndn import Face
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
from pyndn.util import Blob

from threading import Thread
import struct
import time
import hashlib

import binascii
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

user_name = Name('/ndn/ucla.edu/bms/users/public')

from RepoSocketPublisher import RepoSocketPublisher

class Closure(object):
    def __init__(self, bld_root, keychain, cert_name, key, timestamp):
        self.flag_terminate = 0
        self.keychain = keychain
        self.cert_name = cert_name
        #self.prefix = Name('/ndn/ucla.edu/bms/melnitz/kds')
        self.prefix = bld_root.append('kds')
        self.symkey = key
        self.timestamp = timestamp
        self.publisher = RepoSocketPublisher(12345)

    def onData(self, interest, data):
        print data.getName().toUri()
        usr_pubkey = str(bytearray(data.getContent().toBuffer()))
        # Publish sym key
        usrkey = RSA.importKey(usr_pubkey)
        keyid = hashlib.sha256(usrkey.publickey().exportKey("DER")).digest()
        cipher = PKCS1_v1_5.new(usrkey)
        ciphertext = cipher.encrypt(self.symkey)
        
        symkey_name = self.prefix.append(bytearray(self.timestamp)).append(bytearray(keyid))
        symkey_data = Data(symkey_name)
        symkey_data.setContent(bytearray(ciphertext))
        self.keychain.sign(symkey_data, self.cert_name)

        self.publisher.put(symkey_data)
        print symkey_data.getName().toUri()
        self.flag_terminate = 1

    def onTimeout(self, interest):
        print "Time out for interest " + interest.getName().toUri()
        self.flag_terminate = 1

class KDSPublisher(Thread):
    def  __init__(self, bld_root, keychain, cert_name, symkey, timestamp):
        Thread.__init__(self)
        self.bld_root = bld_root
        self.keychain = keychain
        self.cert_name = cert_name
        self.symkey = binascii.hexlify(symkey)
        self.timestamp = timestamp
        self.face = Face("localhost")

    def run(self):
        print 'KDS start'
        closure = Closure(self.bld_root, self.keychain, self.cert_name, self.symkey, self.timestamp)

        self.face.expressInterest(user_name, closure.onData, closure.onTimeout)

        while(closure.flag_terminate == 0):
            self.face.processEvents()
            time.sleep(0.01)

        print 'KDS stop'

# Only for testing
if __name__ == "__main__":
    identityStorage = MemoryIdentityStorage()
    privateKeyStorage = MemoryPrivateKeyStorage()
    keyChain = KeyChain(IdentityManager(identityStorage, privateKeyStorage))
    key_file = "../keychain/keys/melnitz_root.pem"
    f = open(key_file, "r")
    key = RSA.importKey(f.read())
    keyid = hashlib.sha256(key.publickey().exportKey("DER")).digest()
    bld_root = Name("/ndn/ucla.edu/bms/melnitz")
    key_name = bld_root.append(bytearray(keyid))
    key_pub_der = bytearray(key.publickey().exportKey(format="DER"))
    key_pri_der = bytearray(key.exportKey(format="DER"))
    identityStorage.addKey(key_name, KeyType.RSA, Blob(key_pub_der))
    privateKeyStorage.setKeyPairForKeyName(key_name, key_pub_der, key_pri_der)
    cert_name = key_name.getSubName(0, key_name.size() - 1).append(
        "KEY").append(key_name[-1]).append("ID-CERT").append("0")

    time_t = int(time.time() * 1000)
    time_s = struct.pack("!Q", time_t)

    key = Random.new().read(32)
    kds_thread = KDSPublisher(bld_root, keyChain, cert_name, key, time_s)
    kds_thread.start()

    time.sleep(5)
    print "Done"
