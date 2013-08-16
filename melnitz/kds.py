import pyccn
from pyccn import _pyccn

import user_list

from threading import Thread
import struct
import socket

import binascii
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import re

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
        self.anchors = [{'name':'/ndn/ucla.edu/bms/melnitz/%C1.M.K%00%B1%D2%02V%08%FB%AE%2Bf%3B%D6%E3%83%DDr%CE%9A%98%9F-%BB%BCH%20l%A7hGgni%3E','namespace': '/ndn/ucla.edu/bms/melnitz', 'pubkey': \
                             '0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xa0\x11\xc4\x86\xe8\x83\x1e\xa6\x19M\xa3\x07z\xfd\x8d\xab\xe6\xd1<l\xba\xa9\xf1@\xb8\x8d\xbc\x80p\xbf\xe0\xf2cQJ:\xb9\xbaca\xa0\x0cU0.\x99\xedS\xdc\x0f\xcd\x00\x92\xd0\x96\x01\xac~L\xf4\xa92\xe9\xceL\xce\x17\x8b\xf0q\xc7Y\xa1\xd3\x13\xc1\x81\xaf\x12/\xed$,Sy\xf7\xb7\x06"w[\xc9\xd7\x969E\xa3,\x13\xa3\xc0B\x1a\xb5\x11\xb9\xdc\xa0\xbbl\xf9q\xb9Is\xd7m,A\xd4r]9f\xb3\xaf\xf2\t\x02\x03\x01\x00\x01'}]
        self.rules = [# rule for 'data' sub-namespace
	{'key_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/data)/%C1.M.K[^/]+$"),'key_pat_ext':0, 'data_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/data(?:/[^/]+)*)$"), 'data_pat_ext':0 },

	# rule for 'kds' sub-namespace
	{ 'key_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/kds)/%C1.M.K[^/]+$"), 'key_pat_ext':0, 'data_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/kds(?:/[^/]+)*)$"), 'data_pat_ext': 0 },

	#rule for 'users' sub-namespace
	{ 'key_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/users)/%C1.M.K[^/]+$"), 'key_pat_ext': 0, 'data_pat': re.compile("^(/ndn/ucla.edu/bms/melnitz/users(?:/[^/]+)*)$"), 'data_pat_ext': 0 }]
        self.stack = []

    def authorize_by_anchor (self, data_name, key_name):
        # _LOG.debug ("== authorize_by_anchor == data: [%s], key: [%s]" % (data_name, key_name))

        for anchor in self.anchors:
            if key_name == anchor['name']:
                namespace_key = anchor['namespace']
                if namespace_key[:] == data_name[0:len (namespace_key)]:
                    return anchor['pubkey']
            
        return None

    def authorize_by_rule (self, data_name, key_name): 
        for rule in self.rules:
            matches_key = rule['key_pat'].match(key_name)
            if matches_key != None:
                matches_data = rule['data_pat'].match(data_name)
            
                if matches_data != None:
                    namespace_key_t = rule['key_pat'].findall(key_name)
                    namespace_key = namespace_key_t[rule['key_pat_ext']]
                    namespace_data_t =  rule['data_pat'].findall(data_name)
                    namespace_data = namespace_data_t[rule['data_pat_ext']]
                
                    if len (namespace_key) == 0 or namespace_key[:] == namespace_data[:len (namespace_key)]:
                        return True
        return False


    def upcall(self, kind, upcallInfo):
        global flag_terminate
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            
            keylocator =str(co.signedInfo.keyLocator.keyName)
            anchor_pubkey = self.authorize_by_anchor(str(co.name),keylocator)
            if anchor_pubkey !=None:
                root_key = pyccn.Key()
                root_key.fromDER(public = anchor_pubkey)
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

            elif self.authorize_by_rule(str(co.name),keylocator)==True:
                self.stack.append(co)
                handler.expressInterest(pyccn.Name(keylocator),self,interest_tmpl)
            else:
                print "verification failed"
                flag_terminate = 1
                
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
            
      


       
                
