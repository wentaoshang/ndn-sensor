import os, socket
import pyccn
from pyccn import _pyccn

import random

keyFile = "sensor.pem"

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

publisher = RepoSocketPublisher(12345)
prefix = pyccn.Name(["wentao.shang","logtest","key"])
key = pyccn.Key()
key.fromPEM(filename = keyFile)
keyName = prefix.appendKeyID(key).appendVersion().appendSegment(0)

key_co = pyccn.ContentObject()
key_co.name = keyName
key_co.content = key.publicToDER()
key_co.signedInfo = pyccn.SignedInfo(key.publicKeyID, pyccn.KeyLocator(key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
key_co.sign(key)
publisher.put(key_co)
