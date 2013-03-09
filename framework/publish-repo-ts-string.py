import os, random, socket
import pyccn
from pyccn import _pyccn

import time
# from time import gmtime, strftime
from threading import Thread
import json
import struct
import random

keyFile = "sensor.pem"

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataLogger(Thread):
	def __init__(self, data_interval):
		Thread.__init__(self)
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name(["wentao.shang","logtest1"]).appendVersion()
		self.interval = data_interval # in milliseconds
		
		self.start_time = int(time.time() * 1000) # time.time() returns float point time in seconds since epoch
		
		if data_interval >= 1000:
			self.aggregate = 1 # put 1 samples in one packet if the interval is large ( may have higher overhead!!! )
		else:
			self.aggregate = int(1000 / data_interval) # limit data rate to be 1 packet per second
		
		self.loadAndPublishKey()
		
		#self.publishMetaInfo()
		
		
	def loadAndPublishKey(self):
		self.key = pyccn.Key()
		self.key.fromPEM(filename = keyFile)
		self.keyName = self.prefix.append("keys").appendKeyID(self.key).appendVersion().appendSegment(0)
		self.si = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyName), freshness = 1200)
		
		key_co = pyccn.ContentObject()
		key_co.name = self.keyName
		key_co.content = self.key.publicToDER()
		key_co.signedInfo = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
		key_co.sign(self.key)
		self.publisher.put(key_co)

	def publishMetaInfo(self):
		report = {'prefix': str(self.prefix), 'unit': 'mV', 'start': self.start_time, 'interval': self.interval, 'aggregate': self.aggregate}
		
		co = pyccn.ContentObject()
		co.name = self.prefix.append("meta_info")
		co.content = json.dumps(report)
		co.signedInfo = self.si
		co.sign(self.key)
		self.publisher.put(co)
		
	def run(self):
		print "child thread started..."
		# For test purpose, run for 10 seconds only
		# Push content to repo every second
		i = 40
		sample_count = 1
		data_list = []
		
		while (i > 0):
			# now = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
			now = int(time.time() * 1000000000) # in nanoseconds
			
			entry = {'ts': now, 'val': random.randint(0,1000)}
			data_list.append(entry)
			
			if sample_count % self.aggregate == 0:
				payload = {'data':data_list}
				timestamp = str(data_list[0]['ts'])
				
				co = pyccn.ContentObject()
				co.name = self.prefix.append("index").append(timestamp)
				co.content = json.dumps(payload)
				co.signedInfo = self.si
				co.sign(self.key)
				self.publisher.put(co)
				
				sample_count = 0
				data_list = []
			
			i = i - 1
			sample_count = sample_count + 1
			time.sleep(self.interval / 1000.0)
		
		print "leave child thread"

if __name__ == "__main__":
	print "main thread started..."
	logger = SensorDataLogger(data_interval = 100)
	logger.start()
	logger.join()
	print "leave main thread"
	