keyfile_folder = 'keys/'

# Hash table mapping key names to key file names
keyfiles = { \
'/ndn/ucla.edu/bms' : 'bms_root.pem', \
'/ndn/ucla.edu/bms/melnitz' : 'melnitz_root.pem', \
'/ndn/ucla.edu/bms/melnitz/data' : 'data_root.pem', \
'/ndn/ucla.edu/bms/melnitz/kds' : 'kds_root.pem', \
'/ndn/ucla.edu/bms/melnitz/users' : 'user_root.pem', \
'/ndn/ucla.edu/bms/melnitz/users/public' : 'pub_user.pem' \
}

# Each element in the array is a pair representing (signee_name, signer_name)
# where signer'key signs signee's key
keychain = [ \
('/ndn/ucla.edu/bms', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/melnitz', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/melnitz/data', '/ndn/ucla.edu/bms/melnitz'), \
('/ndn/ucla.edu/bms/melnitz/kds', '/ndn/ucla.edu/bms/melnitz'), \
('/ndn/ucla.edu/bms/melnitz/users', '/ndn/ucla.edu/bms/melnitz'), \
('/ndn/ucla.edu/bms/melnitz/users/public', '/ndn/ucla.edu/bms/melnitz/users') \
]

