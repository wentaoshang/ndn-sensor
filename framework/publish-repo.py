import os, random, socket
import pyccn
from pyccn import _pyccn

import time
# from time import gmtime, strftime
from threading import Thread
import json

import random

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SystemTimeLogger(Thread):
	def __init__(self):
		Thread.__init__(self)
		self.publisher = RepoSocketPublisher(12345)
		self.prefix = pyccn.Name(["wentao.shang","logtest"])
		self.key = pyccn.CCN.getDefaultKey()
		self.si = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key), freshness = 1200)
		
	def run(self):
		print "child thread started..."
		# For test purpose, run for 10 seconds only
		# Push content to repo every second
		i = 20
		sample_count = 1
		data_list = []
		while (i > 0):
			# now = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
			now = int(time.time() * 1000)
			
			entry = {'ts':now, 'value':random.randint(0,1000)}
			data_list.append(entry)
			
			if sample_count % 10 == 0:
				report = {'data':data_list}
				data_list = []
				json_text = json.dumps(report)
				
				co = pyccn.ContentObject()
				co.name = self.prefix.appendVersion()
				co.content = json_text
				co.signedInfo = self.si
				co.sign(self.key)
				self.publisher.put(co)
			
			i = i - 1
			sample_count = sample_count + 1
			time.sleep(0.1)
		
		print "leave child thread"

if __name__ == "__main__":
	print "main thread started..."
	logger = SystemTimeLogger()
	logger.start()
	logger.join()
	print "leave main thread"
	