import os, random, socket
import pyccn
from pyccn import _pyccn

class RepoSocketPublisher(pyccn.Closure):
	def __init__(self, repo_port):
		self.repo_dest = ('127.0.0.1', int(repo_port))

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(self.repo_dest)

	def put(self, content):
		self.sock.send(_pyccn.dump_charbuf(content.ccn_data))


n = pyccn.Name(["wentao.shang","repotest"])

k = pyccn.CCN.getDefaultKey()
si = pyccn.SignedInfo(k.publicKeyID, pyccn.KeyLocator(k), freshness = 1200)

co = pyccn.ContentObject()
co.name = n
co.content = "Push some content to repo"
co.signedInfo = si
co.sign(k)

publisher = RepoSocketPublisher(12345)
publisher.put(co)