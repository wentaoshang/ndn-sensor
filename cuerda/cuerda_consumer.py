import socket, time
import json

import pyccn
from pyccn import _pyccn


c = pyccn.CCN()

n = pyccn.Name(["wentao.shang","cuerda1"])

i = pyccn.Interest(childSelector = 1, answerOriginKind = pyccn.AOK_NONE)

co = c.get(n, i, 100)

last = ''

# print co

name = co.name[0:3].append('index')

while (True):
	co = c.get(name, i, 100)
	
	if co != None and co.name[-1] != last:
			print co.name
			last = co.name[-1]
		
	time.sleep(0.005)