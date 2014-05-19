import hashlib

def getKeyID(key):
    pub_der = key.publickey().exportKey(format="DER")
    return bytearray(hashlib.sha256(pub_der).digest())

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]
