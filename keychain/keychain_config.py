keyfile_folder = 'keys/'

# Hash table mapping identity names to key file names
keyfiles = { \
'/ndn/ucla.edu/bms' : 'bms_root.pem', \
'/ndn/ucla.edu/bms/melnitz' : 'melnitz_root.pem', \
'/ndn/ucla.edu/bms/strathmore' : 'strathmore_root.pem', \
'/ndn/ucla.edu/bms/users' : 'user_root.pem', \
'/ndn/ucla.edu/bms/users/public' : 'pub_user.pem' \
}

# Each element in the array is a pair representing (signee_name, signer_name)
# where signer'key signs signee's key
keychain = [ \
('/ndn/ucla.edu/bms', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/melnitz', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/strathmore', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/users', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/users/public', '/ndn/ucla.edu/bms/users') \
]

