import socket, time
import json
import struct
from random import random
from threading import Thread

import pyccn
from pyccn import _pyccn

keyFile = "cuerda.pem"

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataProducer(Thread):
	def __init__(self):
		Thread.__init__(self)
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name("/ndn/ucla.edu/apps/cuerda/sensor/accelerometer").appendVersion()
		
		self.loadAndPublishKey()
		
	def loadAndPublishKey(self):
		self.key = pyccn.Key()
		self.key.fromPEM(filename = keyFile)
		self.keyName = self.prefix.append("keys").appendKeyID(self.key).appendSegment(0)
		self.si = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyName))
		
		key_co = pyccn.ContentObject()
		key_co.name = self.keyName
		key_co.content = self.key.publicToDER()
		key_co.signedInfo = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
		key_co.sign(self.key)
		self.publisher.put(key_co)
		
	def run(self):
		while (True):
			now = int(time.time() * 1000000) # in microseconds
			
			#print str(int(time.time() * 1000000)) + ": " + str(content)
			
		 	entry = {'ts': now, 'acx': random() * 20.0, 'acy': random() * 100.0, 'acz': random() * 50.0}
		
			timestamp = struct.pack("!Q", now) # timestamp is in milliseconds
			
			co = pyccn.ContentObject()
			co.name = self.prefix.append("index").append(timestamp)
			co.content = json.dumps(entry)
			co.signedInfo = self.si
			co.sign(self.key)
			self.publisher.put(co)
			
			time.sleep(0.005)
				

if __name__ == "__main__":
	producer = SensorDataProducer()
	producer.start()
	producer.join()
