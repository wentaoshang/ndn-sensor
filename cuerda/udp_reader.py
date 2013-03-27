import socket, time
import json
import struct
from threading import Thread

import pyccn
from pyccn import _pyccn

keyFile = "sensor.pem"

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataProducer(Thread):
	def __init__(self, aggregate):
		Thread.__init__(self)
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name("/ndn/ucla.edu/apps/cuerda/sensor/accelerometer").appendVersion()
		
		self.aggregate = aggregate
		
		self.udp_reader = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.udp_reader.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.udp_reader.bind(('192.168.42.255', 9750))
		
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
		sample_count = 1
		data_list = []
		buf = ''
		
		while (True):
			content, addr_info = self.udp_reader.recvfrom(128)
			#print content
			
			now = int(time.time() * 1000000) # in microseconds
			
			buf += content
			pos = buf.find('\n')
			if pos != -1:
				#print str(int(time.time() * 1000000)) + ": " + str(content)
				
				data = buf[0 : (pos + 1)].split(',')
				
				buf = buf[(pos + 1) : len(buf)]
				#print data[7][0:data[7].index('*')]
				#print data
				
				try:
			 		entry = {'ts': now, 'q0': float(data[1]), 'q1': float(data[2]), 'q2': float(data[3]), 'q3': float(data[4]), 'acx': float(data[5]), 'acy': float(data[6]), 'acz': float(data[7][0:data[7].index('*')])}
				except:
					print data
					continue
				
				if self.aggregate != 1:
					data_list.append(entry)
					if sample_count % self.aggregate == 0:
						payload = {'data':data_list}
						timestamp = struct.pack("!Q", int(data_list[0]['ts'])) # timestamp is in milliseconds
				
						co = pyccn.ContentObject()
						co.name = self.prefix.append("index").append(timestamp)
						co.content = json.dumps(payload)
						co.signedInfo = self.si
						co.sign(self.key)
						self.publisher.put(co)
				
						sample_count = 0
						data_list = []
			
					sample_count = sample_count + 1
				else:
					timestamp = struct.pack("!Q", now) # timestamp is in milliseconds
					
					co = pyccn.ContentObject()
					co.name = self.prefix.append("index").append(timestamp)
					co.content = json.dumps(entry)
					co.signedInfo = self.si
					co.sign(self.key)
					self.publisher.put(co)
				

if __name__ == "__main__":
	producer = SensorDataProducer(1)
	producer.start()
	producer.join()