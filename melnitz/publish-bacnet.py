#!/usr/bin/python

"""
Based on sample005.py
"""

import sys
import logging

from ConfigParser import ConfigParser

from bacpypes.debugging import Logging, ModuleLogger
from bacpypes.consolelogging import ConsoleLogHandler
from bacpypes.consolecmd import ConsoleCmd

from bacpypes.core import run

from bacpypes.pdu import Address, GlobalBroadcast
from bacpypes.app import LocalDeviceObject, BIPSimpleApplication
from bacpypes.object import get_object_class, get_datatype

from bacpypes.apdu import WhoIsRequest, IAmRequest, ReadPropertyRequest, Error, AbortPDU, ReadPropertyACK
from bacpypes.primitivedata import Unsigned
from bacpypes.constructeddata import Array
from bacpypes.basetypes import ServicesSupported
from bacpypes.errors import DecodingError

import os, random, socket
import ndn

import binascii
from Crypto.Cipher import AES
from Crypto import Random

from threading import Thread

import time
import json
import struct

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

key = binascii.unhexlify('389ad5f8fc26f076e0ba200c9b42f669d07066032df8a33b88d49c1763f80783')

# some debugging
_debug = 0
_log = ModuleLogger(globals())

key_file = "tv1.pem"

sample_count = 1
data_cache = []
packet_ts = 0

bac_app = None

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(content.get_ccnb())

class BACnetAggregator(BIPSimpleApplication, Logging):

    def __init__(self, config):
        if _debug: BACnetAggregator._debug("__init__ %r", config)

        # get local address from the config file
        laddr = config.get('BACpypes', 'address')
        
        # make a local device object
        local_device = \
          LocalDeviceObject( objectName=config.get('BACpypes','objectName')
                             , objectIdentifier=config.getint('BACpypes','objectIdentifier')
                             , maxApduLengthAccepted=config.getint('BACpypes','maxApduLengthAccepted')
                             , segmentationSupported=config.get('BACpypes','segmentationSupported')
                             , vendorIdentifier=config.getint('BACpypes','vendorIdentifier')
              )
        
        # build a bit string that knows about the bit names
        pss = ServicesSupported()
        pss['whoIs'] = 1
        pss['iAm'] = 1
        pss['readProperty'] = 1
        pss['writeProperty'] = 1
        
        # set the property value to be just the bits
        local_device.protocolServicesSupported = pss.value
        
        # make a simple application
        BIPSimpleApplication.__init__(self, local_device, laddr)

        # create logger
        self.logger = BACnetDataLogger(self, config)

        # keep track of requests to line up responses
        self._request = None

    def request(self, apdu):
        if _debug: BACnetAggregator._debug("request %r", apdu)

        # save a copy of the request
        self._request = apdu

        # forward it along
        BIPSimpleApplication.request(self, apdu)

    def confirmation(self, apdu):
        global sample_count, data_cache, packet_ts
        
        if _debug: BACnetAggregator._debug("confirmation %r", apdu)

        if isinstance(apdu, Error):
            sys.stdout.write("error: %s\n" % (apdu.errorCode,))
            sys.stdout.flush()

        elif isinstance(apdu, AbortPDU):
            apdu.debug_contents()

        elif (isinstance(self._request, ReadPropertyRequest)) and (isinstance(apdu, ReadPropertyACK)):
            # find the datatype
            datatype = get_datatype(apdu.objectIdentifier[0], apdu.propertyIdentifier)
            BACnetAggregator._debug("    - datatype: %r", datatype)
            if not datatype:
                raise TypeError, "unknown datatype"

            # special case for array parts, others are managed by cast_out
            if issubclass(datatype, Array) and (apdu.propertyArrayIndex is not None):
                if apdu.propertyArrayIndex == 0:
                    value = apdu.propertyValue.cast_out(Unsigned)
                else:
                    value = apdu.propertyValue.cast_out(datatype.subtype)
            else:
                value = apdu.propertyValue.cast_out(datatype)
            BACnetAggregator._debug("    - value: %r", value)

            #sys.stdout.write(str(value) + '\n')
            #sys.stdout.flush()

            now = int(time.time() * 1000) # in milliseconds
            if packet_ts == 0:
                packet_ts = now

            # package into JSON
            entry = {'ts': now, 'pw': value}
            data_cache.append(entry)
			
            if sample_count % self.logger.aggregate == 0:
                payload = {'data':data_cache}
                timestamp = struct.pack("!Q", packet_ts) # timestamp is in milliseconds

                self.logger.publish_data(payload, timestamp)
                
                sample_count = 0
                data_cache = []
                packet_ts = 0
            
            sample_count = sample_count + 1

            #
            # We could move the 'sleep&read' looping into logger thread so
            # that we could parallel read and write processes. For now we
            # only work on a single thread. The logger thread simply kicks 
            # off the initial request and then exits.
            #
            time.sleep(self.logger.interval)
            self.logger.do_read()

    def indication(self, apdu):
        if _debug: BACnetAggregator._debug("indication %r", apdu)

        if (isinstance(self._request, WhoIsRequest)) and (isinstance(apdu, IAmRequest)):
            device_type, device_instance = apdu.iAmDeviceIdentifier
            if device_type != 'device':
                raise DecodingError, "invalid object type"

            if (self._request.deviceInstanceRangeLowLimit is not None) and \
                (device_instance < self._request.deviceInstanceRangeLowLimit):
                pass
            elif (self._request.deviceInstanceRangeHighLimit is not None) and \
                (device_instance > self._request.deviceInstanceRangeHighLimit):
                pass
            else:
                # print out the contents
                sys.stdout.write('pduSource = ' + repr(apdu.pduSource) + '\n')
                sys.stdout.write('iAmDeviceIdentifier = ' + str(apdu.iAmDeviceIdentifier) + '\n')
                sys.stdout.write('maxAPDULengthAccepted = ' + str(apdu.maxAPDULengthAccepted) + '\n')
                sys.stdout.write('segmentationSupported = ' + str(apdu.segmentationSupported) + '\n')
                sys.stdout.write('vendorID = ' + str(apdu.vendorID) + '\n')
                sys.stdout.flush()

        # forward it along
        BIPSimpleApplication.indication(self, apdu)

class BACnetDataLogger(Thread):
    def __init__(self, app, config):
        Thread.__init__(self)

        # pointer to aggregator app
        self.app = app

        self.foreign_addr = config.get('BACpypes', 'foreignBBMD')
		
        # connect to local repo
        self.publisher = RepoSocketPublisher(12345)
        self.prefix = ndn.Name("/ndn/ucla.edu/apps/cps/sec/melnitz/TV1/PanelJ").appendVersion()
        self.interval = 1.0 # in seconds
		
        self.aggregate = 60 # 60 samples per content object
		
        self.loadKey()
        
    def loadKey(self):
        self.key = ndn.Key()
        self.key.fromPEM(filename = key_file)
        self.key_name = ndn.Name("/ndn/ucla.edu/apps/cps/sec/melnitz/TV1/PanelJ").append("keys").appendKeyID(self.key)
        self.si = ndn.SignedInfo(self.key.publicKeyID, ndn.KeyLocator(self.key_name))
        
        #key_co = pyccn.ContentObject()
        #key_co.name = self.key_name
        #key_co.content = self.key.publicToDER()
        #key_co.signedInfo = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.key), type = pyccn.CONTENT_KEY, final_block = b'\x00')
        #key_co.sign(self.key)
        #self.publisher.put(key_co)
        
    def run(self):
        # wait for the BACnet service to start
        time.sleep(1.0)

        # make the initial request to kick off the 'sleep&read' loop
        self.do_read()

        # and exit...

    def publish_data(self, payload, timestamp):
        co = ndn.ContentObject()
        co.name = self.prefix.append("index").append(timestamp)
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        co.content = iv + encryptor.encrypt(pad(json.dumps(payload)))
        co.signedInfo = self.si
        co.sign(self.key)
        self.publisher.put(co)
                
    def do_read(self):
        try:
            # query the present value of 'MLNTZ.PNL.J.DEMAND'
            obj_type = 'analogInput'
            obj_inst = 0
            prop_id = 'presentValue'
            
            if not get_object_class(obj_type):
                raise ValueError, "unknown object type: " + obj_type

            datatype = get_datatype(obj_type, prop_id)
            if not datatype:
                raise ValueError, "invalid property for object type: " + prop_id

            # build a request
            request = ReadPropertyRequest(
                objectIdentifier=(obj_type, obj_inst),
                propertyIdentifier=prop_id,
                )
            request.pduDestination = Address(self.foreign_addr)

            # give it to the application
            self.app.request(request)

        except Exception, e:
            _log.exception("exception: %r", e)

#
#   __main__
#

try:
    if ('--buggers' in sys.argv):
        loggers = logging.Logger.manager.loggerDict.keys()
        loggers.sort()
        for loggerName in loggers:
            sys.stdout.write(loggerName + '\n')
        sys.exit(0)

    if ('--debug' in sys.argv):
        indx = sys.argv.index('--debug')
        for i in range(indx+1, len(sys.argv)):
            ConsoleLogHandler(sys.argv[i])
        del sys.argv[indx:]

    _log.debug("initialization")

    # read in a configuration file
    config = ConfigParser()
    if not config.read('BACpypes.ini'):
        raise RuntimeError, "configuration file not found"


    bac_app = BACnetAggregator(config)
    
    _log.debug("running")

    # start logger thread
    bac_app.logger.start()

    # start bacnet service
    run()

    bac_app.logger.join()


except Exception, e:
    _log.exception("an error has occurred: %s", e)
finally:
    _log.debug("finally")
