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
from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import Sha256WithRsaSignature
from pyndn.security import KeyType
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.util import Blob

import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

import thread
from threading import Thread

import time
import json
import struct

from data_points import datapoints

sys.path.append("../common/")
import kds
from utils import *
from RepoSocketPublisher import RepoSocketPublisher

key = binascii.unhexlify('389ad5f8fc26f076e0ba200c9b42f669d07066032df8a33b88d49c1763f80783')

# some debugging
_debug = 0
_log = ModuleLogger(globals())

key_file = "../keychain/keys/melnitz_root.pem"
bld_root = "/ndn/ucla.edu/bms/melnitz"
point_count = 0
kds_count = 0
time_s = struct.pack("!Q", 0)

bac_app = None

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
        self.loadKey()
        # keep track of requests to line up responses
        self._request = None

        # connect to local repo
        self.publisher = RepoSocketPublisher(12345)
        self.interval = 5 # in seconds
    
    def loadKey(self):
        self.identityStorage = MemoryIdentityStorage()
        self.privateKeyStorage = MemoryPrivateKeyStorage()
        self.keychain = KeyChain(IdentityManager(self.identityStorage, self.privateKeyStorage))

        f = open(key_file, "r")
        self.key = RSA.importKey(f.read())
        self.key_name = Name(bld_root).append(getKeyID(self.key))
        key_pub_der = bytearray(self.key.publickey().exportKey(format="DER"))
        key_pri_der = bytearray(self.key.exportKey(format="DER"))
        self.identityStorage.addKey(self.key_name, KeyType.RSA, Blob(key_pub_der))
        self.privateKeyStorage.setKeyPairForKeyName(self.key_name, key_pub_der, key_pri_der)
        self.cert_name = self.key_name.getSubName(0, self.key_name.size() - 1).append(
            "KEY").append(self.key_name[-1]).append("ID-CERT").append("0")

        print 'KeyName = ' + self.key_name.toUri()
        print 'CertName = ' + self.cert_name.toUri()

    def publishData(self, name_str, payload, timestamp):
        data = Data(Name(name_str).append(bytearray(timestamp)))
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        data.setContent(bytearray(time_s + iv + encryptor.encrypt(pad(json.dumps(payload)))))
        self.keychain.sign(data, self.cert_name)
        self.publisher.put(data)
        #print payload
        #print 'Publish ' + data.getName().toUri()

    def request(self, apdu):
        if _debug: BACnetAggregator._debug("request %r", apdu)

        # save a copy of the request
        self._request = apdu

        # forward it along
        BIPSimpleApplication.request(self, apdu)

    def confirmation(self, apdu):
        #print thread.get_ident()
        global kds_count, key, time_s, point_count
        
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

            # KDS
            if kds_count % 1200 == 0:
                time_t = int(time.time() * 1000)
                time_s = struct.pack("!Q", time_t)
                
                key = Random.new().read(32)
                kds_thread = kds.SimpleKDSPublisher(Name(bld_root), self.keychain, self.cert_name, key, time_s)
                kds_thread.start()
                kds_count = 0

            kds_count = kds_count + 1
            #
            
            now = int(time.time() * 1000) # in milliseconds
            
            payload = {'ts': now, 'val': value}
            
            timestamp = struct.pack("!Q", now)
            self.publishData(datapoints[point_count]['prefix'], payload, timestamp)
            point_count = (point_count + 1) % len(datapoints)

            #
            #
            # We could move the 'sleep&read' looping into logger thread so
            # that we could parallel read and write processes. For now we
            # only work on a single thread. The logger thread simply kicks 
            # off the initial request and then exits.
            #
            time.sleep(self.interval)
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

    def run(self):
        print "Logger thread started..."

        # wait for the BACnet service to start
        time.sleep(1.0)

        print "Make initial BACnet reqeust to the device"

        # make the initial request to kick off the 'sleep&read' loop
        self.do_read()

        # and exit...
        print "Logger thread terminate"
        
    def do_read(self):
        try:
            # query the present value of 'MLNTZ.PNL.J.DEMAND'
            obj_type = datapoints[point_count]['obj_type']
            obj_inst = datapoints[point_count]['obj_inst']
            prop_id =  datapoints[point_count]['prop_id']
            
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

    #print thread.get_ident()

    print "In main thread: start logger thread..."

    # start logger thread
    bac_app.logger.start()

    print "In main thread: enter BACnet service loop..."

    # start bacnet service
    run()

    print "In main thread: wait for logger thread to exit..."

    bac_app.logger.join()

    print "In main thread: logger.join() returned"


except Exception, e:
    _log.exception("an error has occurred: %s", e)
finally:
    _log.debug("finally")
