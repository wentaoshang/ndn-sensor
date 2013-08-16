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

#import binascii
#from Crypto.Cipher import AES
#from Crypto import Random

keyFile = "../keychain/keys/strathmore_root.pem"

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
		self.master.set_timeout(100.0)
		
		# connect to local repo
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name("/ndn/ucla.edu/bms/strathmore/data/demand")
		self.interval = data_interval # in seconds
		
		self.aggregate = 60 # 60 samples per content object
		
		self.loadKey()
		
	def loadKey(self):
		self.key = pyccn.Key()
		self.key.fromPEM(filename = keyFile)
		self.key_name = pyccn.Name("/ndn/ucla.edu/bms/strathmore/data").appendKeyID(self.key)
		print 'Use key name ' + str(self.key_name) + ' to sign data'
		self.si = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key_name))
		
	def publishData(self, key_ver, payload, timestamp):
		co = pyccn.ContentObject()
		co.name = self.prefix.append(timestamp)
		#iv = Random.new().read(AES.block_size)
		#encryptor = AES.new(key, AES.MODE_CBC, iv)
		#co.content = key_ver + iv + encryptor.encrypt(pad(json.dumps(payload)))
		co.content = json.dumps(payload)
		co.signedInfo = self.si
		co.sign(self.key)
		self.publisher.put(co)

	def run(self):
		sample_count = 1
		data_list = []
		packet_ts = 0
		key_ver = struct.pack('!Q', 0)
		
		while (True):
			now = int(time.time() * 1000) # in milliseconds
			if packet_ts == 0:
				packet_ts = now

			a = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 166, 1)
 			b = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 167, 1)
			vln = (b[0] << 16) + a[0]
			c = self.master.execute(1, cst.READ_HOLDING_REGISTERS, 150, 1)
			la = c[0]
			
			entry = {'ts': now, 'vlna': vln, 'la': la}
			data_list.append(entry)
			
			if sample_count % self.aggregate == 0:
				payload = {'data':data_list}
				timestamp = struct.pack("!Q", packet_ts) # timestamp is in milliseconds
				
				self.publishData(key_ver, payload, timestamp)
				
				sample_count = 0
				data_list = []
				packet_ts = 0
			
			sample_count = sample_count + 1
			time.sleep(self.interval)

if __name__ == "__main__":
	logger = SensorDataLogger(data_interval = 1.0) # sample at every 1 second
	logger.run()
