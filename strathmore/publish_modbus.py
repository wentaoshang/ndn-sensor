import socket
import pyccn
from pyccn import _pyccn

import time
from threading import Thread
import json
import struct

import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

import kds

import binascii
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

key_file = "../keychain/keys/strathmore_root.pem"

class RepoSocketPublisher(pyccn.Closure):
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataLogger:
    def __init__(self, data_interval):
        # connect to modbus
        self.master = modbus_tcp.TcpMaster("172.17.66.246", 502)
        self.master.set_timeout(1000.0)
        
        # connect to local repo
        self.publisher = RepoSocketPublisher(12345)
        self.prefix = pyccn.Name("/ndn/ucla.edu/bms/strathmore/data/demand")
        self.interval = data_interval # in seconds
        
        self.loadKey()
        
    def loadKey(self):
        self.ksk = pyccn.Key()
        self.ksk.fromPEM(filename = key_file)
        self.ksk_name = pyccn.Name("/ndn/ucla.edu/bms/strathmore").appendKeyID(self.ksk)
        print 'Use key name ' + str(self.ksk_name) + ' as KSK'
        self.ksk_si = pyccn.SignedInfo(self.ksk.publicKeyID, pyccn.KeyLocator(self.ksk_name), type = pyccn.CONTENT_KEY, final_block = b'\x00')
        
        self.data_dsk = pyccn.Key()
        self.data_dsk.generateRSA(1024)
        self.data_dskname = pyccn.Name("/ndn/ucla.edu/bms/strathmore/data").appendVersion().appendKeyID(self.data_dsk)
        self.data_si = pyccn.SignedInfo(self.data_dsk.publicKeyID, pyccn.KeyLocator(self.data_dskname), type = pyccn.CONTENT_KEY, final_block = b'\x00')
        self.publishDSK(self.data_dsk, self.data_dskname)
        self.key = self.data_dsk
        self.si = self.data_si
        print 'Publish data DSK: ' + str(self.data_dskname)
        
        self.kds_dsk = pyccn.Key()
        self.kds_dsk.generateRSA(1024)
        self.kds_dskname = pyccn.Name("/ndn/ucla.edu/bms/strathmore/kds").appendVersion().appendKeyID(self.kds_dsk)
        self.kds_si = pyccn.SignedInfo(self.kds_dsk.publicKeyID, pyccn.KeyLocator(self.kds_dskname), type = pyccn.CONTENT_KEY, final_block = b'\x00')
        self.publishDSK(self.kds_dsk, self.kds_dskname)
        print 'Publish kds DSK: ' + str(self.kds_dskname)
        
    def publishDSK(self, dsk, dsk_name):
        key_co = pyccn.ContentObject()
        key_co.name = dsk_name
        key_co.content = dsk.publicToDER()
        key_co.signedInfo = self.ksk_si
        key_co.sign(self.ksk)
        self.publisher.put(key_co)

    def publishData(self, key, key_ver, payload, timestamp):
        co = pyccn.ContentObject()
        co.name = self.prefix.append(timestamp)
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        co.content = key_ver + iv + encryptor.encrypt(pad(json.dumps(payload)))
        #co.content = json.dumps(payload)
        co.signedInfo = self.si
        co.sign(self.key)
        self.publisher.put(co)

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
                kds_thread = kds.KDSPublisher(key, key_ts, self.kds_dsk, self.kds_si)
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
    logger = SensorDataLogger(data_interval = 1.0)
    logger.run()
