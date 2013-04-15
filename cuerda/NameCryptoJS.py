import pyccn
import hashlib
import hmac
import struct
import time

class State:
	def __init__(self):
		self.tv_sec = 0
		self.tv_usec = 0
		self.seq = 0
		self.rsvd = 0
	
	size = 16
	
	def update(self):
		now = time.time()
		self.tv_sec = int(now)
		self.tv_usec = int((now - self.tv_sec) * 1000000.0)
		self.seq = self.seq + 1
	
	def to_bytes(self):
		return struct.pack('!IIII', self.tv_sec, self.tv_usec, self.seq, self.rsvd)
	
	def from_bytes(self, n_state):
		state = struct.unpack('!IIII', n_state)
		self.tv_sec = state[0]
		self.tv_usec = state[1]
		self.seq = state[2]
		self.rsvd = state[3]

class NameCrypto:
	PK_AUTH_MAGIC = '\x21\x44\x07\x65'
	SK_AUTH_MAGIC = '\x40\x96\x1c\x51'
	AUTH_MAGIC_LEN = 4
	
	@staticmethod
	def generate_shared_key(secret, app_code):
		hh = hashlib.sha256()
		hh.update(app_code)
		app_id = hh.digest()
	
		hasher = hmac.new(secret, digestmod = hashlib.sha256)
		hasher.update(app_id)
		shared_key = hasher.digest()
	
		return shared_key
	
	@staticmethod
	def authenticate_name_symm(state, name, app_code, shared_key):
		state.update()
		n_state = state.to_bytes()
		
		n_name = pyccn._pyccn.dump_charbuf(name.ccn_data)
		
		m_list = []
		m_list.append(n_name)
		m_list.append(app_code)
		m_list.append(n_state)
		m = ''.join(m_list)
		
		hasher = hmac.new(shared_key, digestmod = hashlib.sha256)
		hasher.update(m)
		n_mac = hasher.digest()
		
		app_len = len(app_code)
		n_app_len = struct.pack('!H', app_len)
		
		n_list = []
		n_list.append(NameCrypto.SK_AUTH_MAGIC)
		n_list.append(n_app_len)
		n_list.append(app_code)
		n_list.append(n_state)
		n_list.append(n_mac)
		n = ''.join(n_list)
		
		return name.append(n)
		
	@staticmethod
	def verify_name_symm(name, secret, window, app_code):
		n1 = name[0 : (len(name) - 1)]
		n_crypto = name[-1]

		n1_rstr = pyccn._pyccn.dump_charbuf(n1.ccn_data)

		app_len = (ord(n_crypto[NameCrypto.AUTH_MAGIC_LEN]) << 8) + ord(n_crypto[NameCrypto.AUTH_MAGIC_LEN + 1])  # app_code length
		app_code = n_crypto[(NameCrypto.AUTH_MAGIC_LEN + 2) : (NameCrypto.AUTH_MAGIC_LEN + 2 + app_len)]
		
		n_state = n_crypto[(NameCrypto.AUTH_MAGIC_LEN + 2 + app_len) : (NameCrypto.AUTH_MAGIC_LEN + 2 + app_len + State.size)]
		state = State()
		state.from_bytes(n_state)

		d = state.tv_sec + state.tv_usec / 1000000.0
		now = time.time()
	
		if (d > now) or ((d + window) < now):
			return False

		shared_key = NameCrypto.generate_shared_key(secret, app_code)

		n_mac = n_crypto[(NameCrypto.AUTH_MAGIC_LEN + 2 + app_len + 16):]

		m_list = []
		m_list.append(n1_rstr)
		m_list.append(app_code)
		m_list.append(n_state)
		m = ''.join(m_list)

		hasher = hmac.new(shared_key, digestmod = hashlib.sha256)
		hasher.update(m)
		mac = hasher.digest()

		return (mac == n_mac)