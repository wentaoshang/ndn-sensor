import socket
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

import time
from threading import Thread
import json
import struct

import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

import sys
sys.path.append("../common/")
import kds
from utils import *
from RepoSocketPublisher import RepoSocketPublisher

import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

key_file = "../keychain/keys/strathmore_root.pem"
bld_root = "/ndn/ucla.edu/bms/strathmore"

class SensorDataLogger:
    def __init__(self, data_interval):
        # connect to modbus
        self.master = modbus_tcp.TcpMaster("172.17.66.246", 502)
        self.master.set_timeout(10000.0)
        
        # connect to local repo
        self.publisher = RepoSocketPublisher(12345)
        self.prefix = "/ndn/ucla.edu/bms/strathmore/data/demand"
        self.interval = data_interval # in seconds
        
        self.loadKey()
        
    def loadKey(self):
        self.identityStorage = MemoryIdentityStorage()
        self.privateKeyStorage = MemoryPrivateKeyStorage()
        self.keychain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))

        f = open(key_file, "r")
        self.key = RSA.importKey(f.read())
        self.key_name = Name(bld_root).append(getKeyID(self.key))
        key_pub_der = bytearray(self.key.publickey().exportKey(format="DER"))
        key_pri_der = bytearray(self.key.exportKey(format="DER"))
        self.identityStorage.addKey(self.key_name, KeyType.RSA, Blob(key_pub_der))
        self.privateKeyStorage.setKeyPairForKeyName(self.key_name, key_pub_der, key_pri_der)
        self.cert_name = self.key_name.getSubName(0, self.key_name.size() - 1).append(
            "KEY").append(self.key_name[-1]).append("ID-CERT").append("0")

        print 'KeyName = ' + self.key_name.toUri()
        print 'CertName = ' + self.cert_name.toUri()

    def publishData(self, key, key_ts, payload, timestamp):
        data = Data(Name(self.prefix).append(bytearray(timestamp)))
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        data.setContent(bytearray(key_ts + iv + encryptor.encrypt(pad(json.dumps(payload)))))
        self.keychain.sign(data, self.cert_name)
        self.publisher.put(data)
        #print payload
        print data.getName().toUri()

    def run(self):
        key_ts = struct.pack('!Q', int(time.time() * 1000))
        key = Random.new().read(32)
        kds_count = -1
        
        while (True):
            # KDS
            kds_count = kds_count + 1
            if kds_count % 120 == 0:
                key_ts = struct.pack("!Q", int(time.time() * 1000))
                key = Random.new().read(32)
                kds_thread = kds.KDSPublisher(Name(bld_root), self.keychain, self.cert_name, key, key_ts)
                kds_thread.start()
                kds_count = 0

            # Data
            now = int(time.time() * 1000) # in milliseconds

            a = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 166, 1)
            b = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 167, 1)
            vln = (b[0] << 16) + a[0]
            c = self.master.execute(1, cst.READ_HOLDING_REGISTERS, 150, 1)
            la = c[0]
            
            payload = {'ts': now, 'vlna': vln, 'la': la}
            timestamp = struct.pack("!Q", now) # timestamp is in milliseconds

            self.publishData(key, key_ts, payload, timestamp)

            time.sleep(self.interval)

if __name__ == "__main__":
    logger = SensorDataLogger(data_interval = 5.0)
    logger.run()
