import os, random, socket
import pyccn
from pyccn import _pyccn

import time
# from time import gmtime, strftime
from threading import Thread
import json
import struct

import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp

keyFile = "sensor.pem"

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
		self.master.set_timeout(5.0)
		
		# connect to local repo
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name("/ndn/ucla.edu/apps/cps/strathmore").appendVersion()
		self.interval = data_interval # in seconds
		
		self.aggregate = 60 # 60 samples per content object
		
		self.loadAndPublishKey()
		
		
	def loadAndPublishKey(self):
		self.key = pyccn.Key()
		self.key.fromPEM(filename = keyFile)
		self.keyName = self.prefix.append("key").appendKeyID(self.key).appendSegment(0)
		self.si = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyName))
		
		key_co = pyccn.ContentObject()
		key_co.name = self.keyName
		key_co.content = self.key.publicToDER()
		key_co.signedInfo = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
		key_co.sign(self.key)
		self.publisher.put(key_co)
		
	def run(self):
		sample_count = 1
		data_list = []
		
		while (True):
			now = int(time.time() * 1000000000) # in nanoseconds
			
			a = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 166, 1)
 			b = self.master.execute(100, cst.READ_HOLDING_REGISTERS, 167, 1)
			vln = (b[0] << 16) + a[0]
			c = self.master.execute(1, cst.READ_HOLDING_REGISTERS, 150, 1)
			la = c[0]
			
			entry = {'ts': str(now), 'vlna': vln, 'la': la}
			data_list.append(entry)
			
			if sample_count % self.aggregate == 0:
				payload = {'data':data_list}
				timestamp = struct.pack("!Q", int(int(data_list[0]['ts']) / 1000000)) # timestamp is in milliseconds
				
				co = pyccn.ContentObject()
				co.name = self.prefix.append("index").append(timestamp)
				co.content = json.dumps(payload)
				co.signedInfo = self.si
				co.sign(self.key)
				self.publisher.put(co)
				
				sample_count = 0
				data_list = []
			
			sample_count = sample_count + 1
			time.sleep(self.interval)

if __name__ == "__main__":
	logger = SensorDataLogger(data_interval = 1.0) # sample at every 1 second
	logger.run()
