import pyccn
from pyccn import _pyccn

import user_list

from threading import Thread
import struct
import socket

import binascii
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

handler = pyccn.CCN()

interest_tmpl = pyccn.Interest(scope = 1)

flag_terminate = 0

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class VerificationClosure(pyccn.Closure):
    def __init__(self, roster, key, timestamp):
        self.kds_key = pyccn.Key()
        self.kds_key.fromPEM(filename = '../keychain/keys/kds_root.pem')
        self.prefix = pyccn.Name('/ndn/ucla.edu/bms/melnitz/kds')
        self.kdsname = self.prefix.appendKeyID(self.kds_key)
        self.symkey = key
        self.roster = roster
        self.index = 0
        self.timestamp = timestamp
        self.publisher = RepoSocketPublisher(12345)
        self.anchors = [{'name':'/ndn/ucla.edu/bms/%C1.M.K%00%03a%27%95_%7C%1F%CD%C0E%2B54%00%87%AC%84r%DBg%83%07%5D%F9%03%02p%DB%A9%B8%06%B4', 'pubkey': \
                             '0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xd8\xe8\xa76\xbe|\x99\x1f\x0eO\x8e\xbel\xc1\xed\xfd-p\x8b>\xb1\x0f-\x1b\xf7z#j\xba\x9c\x0c\xa0\x9bh\x08\xfbg\xab\x89\xc7\xb5\xc5\xdb\xde\x90H\xee(F\x17\x86\xaf\xd6O\x12`\x00\xd2)n\x95\x14IV\x1e\xa6\xf4+\xa4\xed1z\x801\x1d\x7f\xbe\xcf3\xd3\xbc\xa7\x83\xda\xe6\x13~\x1e\xc3\xb6\x86\xae\xc96\x16\x8e":c\xa4eg\x11\x85\xa2\xff\xae\xa1\xe4\xc6s28W3\'S.\x87\xc5\x94\'\xf7\x90\xa9\x888c\x02\x03\x01\x00\x01'}]
        self.stack = []

    def upcall(self, kind, upcallInfo):
        global flag_terminate
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            
            keylocator =str(co.signedInfo.keyLocator.keyName)
            
            if keylocator == self.anchors[0]['name']:
                root_key = pyccn.Key()
                root_key.fromDER(public = self.anchors[0]['pubkey'])
                flag = co.verify_signature(root_key)
                while flag == True and len(self.stack)>0:
                    key = pyccn.Key()
                    key.fromDER(public = co.content)
                    flag =  self.stack[len(self.stack)-1].verify_signature(key)
                    
                    co = self.stack.pop()
                
                if len(self.stack) == 0:
                    usrpubkey = co.content
                    #publish
                    usrkey = pyccn.Key()
                    usrkey.fromDER(public = usrpubkey)
                    key_t = RSA.importKey(usrpubkey)
                    cipher = PKCS1_v1_5.new(key_t)
                    ciphertext = cipher.encrypt(self.symkey)
                    
                    userdataname = self.prefix.append(self.timestamp).appendKeyID(usrkey)
                    CO = pyccn.ContentObject(name = userdataname,content = ciphertext,signed_info = pyccn.SignedInfo(self.kds_key.publicKeyID,pyccn.KeyLocator(self.kdsname)))
                    CO.sign(self.kds_key)

                    self.publisher.put(CO)
                    print CO.name

                    self.index = self.index+1
                    if self.index<len(self.roster):
                        nextname = pyccn.Name(self.roster[self.index])
                        handler.expressInterest(nextname,self,interest_tmpl)
                    
                    else:
                        #print "overrrrrrrrrr"
                        flag_terminate = 1
                        #print flag_terminate

            else:
                self.stack.append(co)
                handler.expressInterest(pyccn.Name(keylocator),self,interest_tmpl)
                
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK

class KDSPublisher(Thread):
    def  __init__(self, key, timestamp):
        Thread.__init__(self)
        self.key = binascii.hexlify(key)
        self.timestamp = timestamp

    def run(self):
        global flag_terminate
        print 'Publisher started...'
        closure = VerificationClosure(user_list.usrlist, self.key, self.timestamp)
        first = pyccn.Name(user_list.usrlist[0]);

        handler.expressInterest(first, closure, interest_tmpl)

        while(flag_terminate == 0):
            handler.run(500)
            #print flag_terminate

        print 'Publisher stop'
        flag_terminate = 0
            
      
                    
                
