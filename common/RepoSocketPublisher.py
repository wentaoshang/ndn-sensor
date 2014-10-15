import socket

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('localhost', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, data):
        wire = data.wireEncode()
        self.sock.sendall(str(bytearray(wire.toBuffer())))

if __name__ == "__main__":
    from pyndn import Name
    from pyndn import Data
    from pyndn import ContentType
    from pyndn import KeyLocatorType
    from pyndn import Sha256WithRsaSignature
    from pyndn.security import KeyType
    from pyndn.security import KeyChain
    from pyndn.security.identity import IdentityManager
    from pyndn.security.identity import MemoryIdentityStorage
    from pyndn.security.identity import MemoryPrivateKeyStorage
    from pyndn.security.policy import SelfVerifyPolicyManager
    from pyndn.util import Blob
    from Crypto.PublicKey import RSA

    from utils import getKeyID

    publisher = RepoSocketPublisher(12345)

    data = Data(Name("/localhost/repo-ng/test/001"))
    data.setContent("SUCCESS!")
    data.getMetaInfo().setFreshnessPeriod(1000000)

    identityStorage = MemoryIdentityStorage()
    privateKeyStorage = MemoryPrivateKeyStorage()
    keyChain = KeyChain(IdentityManager(identityStorage, privateKeyStorage), 
                        SelfVerifyPolicyManager(identityStorage))
    keyfile = "../keychain/keys/pub_user.pem"
    f = open(keyfile, "r")
    key = RSA.importKey(f.read())
    key_name = Name("/localhost/repo-ng/test/signer")
    signer_name = Name(key_name).append(getKeyID(key))
    key_pub_der = bytearray(key.publickey().exportKey(format="DER"))
    key_pri_der = bytearray(key.exportKey(format="DER"))
    identityStorage.addKey(signer_name, KeyType.RSA, Blob(key_pub_der))
    privateKeyStorage.setKeyPairForKeyName(signer_name, key_pub_der, key_pri_der)
    cert_name = signer_name.getSubName(0, signer_name.size() - 1).append(
      "KEY").append(signer_name[-1]).append("ID-CERT").append("0")
    keyChain.sign(data, cert_name)
    publisher.put(data)
