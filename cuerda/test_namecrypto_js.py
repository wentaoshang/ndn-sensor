import pyccn
import hashlib
import hmac
import struct
import time

def byte_to_hex( byteStr ):
	return ''.join( [ "%02x" % ord( x ) for x in byteStr ] ).strip()

def generate_shared_key(master_key, app_code):
	hh = hashlib.sha256()
	hh.update(app_code)
	app_id = hh.digest()
	
	n = app_id + app_code
	
	hasher = hmac.new(master_key, digestmod = hashlib.sha256)
	hasher.update(n)
	app_key = hasher.digest()
	
	return app_key


secret = '1234567812345678'

state = pyccn.NameCrypto.new_state()

name = pyccn.Name('/ndn/ucla.edu/apps/cuerda')

app_code = 'cuerda'

app_key = generate_shared_key(secret, app_code)
print byte_to_hex(app_key)

#############################
#     Verification
#############################

name_str = '/ndn/ucla.edu/apps/cuerda/%40%96%1CQ%00%06cuerdaQV6%E9%00%08%E5X%00%00%00%02%00%00%00%00u0%F7%86u%18%D8A%FFo.%EB%EC%19%DBW%3F%15%F7%C7%FA%BD%FF%E7%EF%88%B6S%9C3L4'

n = pyccn.Name(name_str)

n1 = n[0 : (len(n) - 1)]
n_crypto = n[-1]

n1_rstr = pyccn._pyccn.dump_charbuf(n1.ccn_data)

app_len = (ord(n_crypto[4]) << 8) + ord(n_crypto[5])

app_code = n_crypto[6: (6 + app_len)]
n_state = n_crypto[(6 + app_len) : (6 + app_len + 16)]
state = struct.unpack('!IIII', n_state)
print state

d = state[0] + state[1] / 1000000.0
print d
print time.time()

app_key = generate_shared_key(secret, app_code)
print byte_to_hex(app_key)

n_mac = n_crypto[(6 + app_len + 16):]
print byte_to_hex(n_mac)

m = n1_rstr + app_code + n_state

hasher = hmac.new(app_key, digestmod = hashlib.sha256)
hasher.update(m)
mac = hasher.digest()
print byte_to_hex(mac)

print mac == n_mac