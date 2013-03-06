import os, socket
import pyccn
from pyccn import _pyccn

import random

keyFile = "sensor.pem"
keyData = "30819F300D06092A864886F70D010101050003818D0030818902818100D88E5E9F2762DF34FCA94DF0D36397F920D8D78EC2CCF27970A55BFFF8585F21327969758EB9310CF957D3539C9E0AC67C7DE24FAEF3321545BC63E1B3C37885DD8E0B37ABD6DC0DAD357F28765C458198BCED3C536DFDF75B5F0BB30D6163DCB2AAE43FD309AC74AB709C67398351407376C2AC3A889F7330FDE27A24183F2B0203010001"


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
key_co.content = keyData
key_co.signedInfo = pyccn.SignedInfo(key.publicKeyID, pyccn.KeyLocator(key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
key_co.sign(key)
#publisher.put(key_co)
