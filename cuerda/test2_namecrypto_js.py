import NameCryptoJS
import pyccn

state = NameCryptoJS.State()

secret = '1234567812345678'

app_code = 'cuerda'

shared_key = NameCryptoJS.NameCrypto.generate_shared_key(secret, app_code)

name = pyccn.Name('/ndn/ucla.edu/apps/cuerda')

auth_name = NameCryptoJS.NameCrypto.authenticate_name_symm(state, name, app_code, shared_key)

window = 3000

print NameCryptoJS.NameCrypto.verify_name_symm(auth_name, secret, window, app_code)

