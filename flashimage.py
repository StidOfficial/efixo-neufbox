#!/usr/bin/env python
# may 2009 (c) avd <avd@patatrac.info>

"""
flashimage for nb4

Easily flash an nb4 with an full image of 8MB 
and a network connection.

Usage:

 ./flashimage.py <network interface> <full image>

The nb4 need to be in download mode (press service button 
approximately 5 seconds when box booting until it is 
blinking blue).

This program uses the download mode of the CFE soft
for the NB4 box. This program send request for flashing 
all the flash AFTER the CFE part.
Obviously, you can use it without risking to destroy your 
nb4 box because there will be the CFE to recover.

this program remove all the things after CFE. Think to save your config before use it.

This program expect a full image of 8MB (CFE + MAIN + JFFS2 + RESCUE + DSL + NV) but the CFE soft on the nb4 in download mode and without EALL request jump the first 64KB of the image (CFE part) thus does not write the CFE part on the flash. 
So, if you don't have the CFE part and you want build a full image, you can remplace the 64KB of the beginning of the full image by any data.
"""

import sys
import string
import struct
import socket
import time
import os

# defs
ETH_ADDR_BROADCAST = '\xff\xff\xff\xff\xff\xff'

CMD_VERSION = 0x0000
CMD_REQUEST = 0x0001
CMD_DATA = 0x0002
CMD_RESET = 0x0003
CMD_VERIFY = 0x0004

# based on http://dev.efixo.net/browser/trunk/openwrt/target/linux/brcm63xx/files-2.6.21/include/asm-mips/mach-bcm63xx/nb4/box/partition.h
# mapping for 2.x (not used for now)
NB_CFE_OFFSET    = 0x0
NB_CFE_SIZE      = 65536

NB_MAIN_OFFSET   = NB_CFE_OFFSET + NB_CFE_SIZE
NB_MAIN_SIZE     = 5570560

NB_JFFS2_OFFSET  = NB_MAIN_OFFSET + NB_MAIN_SIZE
NB_JFFS2_SIZE    = 655360

NB_RESCUE_OFFSET = NB_JFFS2_OFFSET + NB_JFFS2_SIZE
NB_RESCUE_SIZE   = 1572864

NB_DSL_OFFSET    = NB_RESCUE_OFFSET + NB_RESCUE_SIZE
NB_DSL_SIZE      = 458752

NB_NV_OFFSET     = NB_DSL_OFFSET + NB_DSL_SIZE
NB_NV_SIZE       = 65535

NB_TOTAL_SIZE    = 8388608

counter_wsequence = 0x2300

class Dlcpkt:
        '''dlc packet - stock values in network order'''
        dstaddr = None
        srcaddr = None
        sap = None
        wcmd = None
        wsequence = None
        woffset = None
        wsegment = None
        wlen = None
        bdata = None

        hdr_len = 24
        data_len = 24
        
        def __init__(self):
                self.bzero()

        def __str__(self):
                return self.dstaddr + self.srcaddr  + self.sap + self.wcmd + self.wsequence + self.woffset + self.wsegment + self.wlen + self.bdata

        def bzero(self):
                self.dstaddr = '\x00\x00\x00\x00\x00\x00'
                self.srcaddr = '\x00\x00\x00\x00\x00\x00'
                self.sap = '\x88\x88'
                self.wcmd = '\x00\x00'
                self.wsequence = '\x00\x00'
                self.woffset = '\x00\x00'
                self.wsegment = '\x00\x00'
                self.wlen = '\x00\x00'
                self.bdata = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        def pack(self):
                return self.str()

        def unpack(self, data):
                self.dstaddr = data[:6]
                self.srcaddr = data[6:12]
                self.sap = data[12:14]
                self.wcmd = data[14:16]
                self.wsequence = data[16:18]
                self.woffset = data[18:20]
                self.wsegment = data[20:22]
                self.wlen = data[22:24]
                self.bdata = data[24:]

def eth_ntoa(raw):
        # Convert binary data into a string.
        return ":".join(["%02X" % (ord(ch),) for ch in raw])

def eth_aton(buffer):
        addr =''
        temp = string.split(buffer,':')
        buffer = string.join(temp,'')
        # Split up the hex values and pack.
        for i in range(0, len(buffer), 2):
                addr = ''.join([addr,struct.pack('>B', int(buffer[i: i + 2], 16))],)
        return addr

def i16ton(i16):
        ''' Convert 16 bit integer to network '''
        raw = struct.pack('H', i16)
        return raw

def hex2dec(hex):
        return int(hex, 16)

def dec2hex(dec):
        return "%X" % n

def request(s, dlcpkt):
        s.send(str(dlcpkt))

        resp = s.recv(48);

        return resp

def send_file(s, dlcpkt_w, file):
        global counter_wsequence
        progress_list = [ '|', '/', '-', '\\' ]
        progress_index = 0
        wsegment_h = 0x0000
        woffset_h = 0x0000
        counter = 1

        dlcpkt_r = Dlcpkt()
        dlcpkt_w.wcmd = i16ton(CMD_DATA)

        buf_len = 0x0200

        filesize = os.path.getsize(file)

        f = open(file, "r")

        print ' > send %s (size=%d)' % (file, filesize)
        print ' (please wait while the box erasing the flash from 0x00010000 to 0x007fffff before flashing ...)'

        block = f.read(buf_len)
        while block != '':
                dlcpkt_w.bdata = block
                dlcpkt_w.wsequence = i16ton(counter_wsequence)
                dlcpkt_w.wlen = i16ton(len(block))
                dlcpkt_w.wsegment = i16ton(wsegment_h)
                dlcpkt_w.woffset = i16ton(woffset_h)
                
                s.send(str(dlcpkt_w))
                
                # check
                resp = s.recv(48);
                dlcpkt_r.unpack(resp)

                if dlcpkt_r.wsequence != dlcpkt_w.wsequence:
                        print 'FAILED.'
                        break
                else:
                        sys.stdout.write('\r' + progress_list[progress_index] + " %02.f%%" % ( ((counter * len(block)) / (filesize * 1.0)) * 100 ))
                        sys.stdout.flush()

                        progress_index = (progress_index + 1) % len(progress_list)

                ### INCR ###
                # final address = segment<<4 + offset
                wsegment_h = (wsegment_h + (len(block)/0x10)) % (0x10000)
                woffset_h = (wsegment_h & 0x000f)
                
                counter_wsequence = (counter_wsequence + 1) % (0x10000)
                counter = counter + 1
                        
                # new read
                block = f.read(buf_len)
                
                # don't be too speedy
                time.sleep(0.002)

        print ' '
        
        f.close()

###### MAIN ######

if len(sys.argv) < 3:
        print 'Usage: %s <network interface> <full image>' % (sys.argv[0])
        sys.exit(0)

# stock args
dev = sys.argv[1]
firm = sys.argv[2]

# check firmware first
try:
        firmsize = os.path.getsize(firm)
except Exception, e:
        sys.stderr.write("%s\n" % (str(e)));
        sys.exit(1)

if firmsize > NB_TOTAL_SIZE:
        sys.stderr.write("Error, The size of the firmware should not exceed %d bytes otherwise the CFE might be compromised (%s - %d bytes)\n" % (NB_TOTAL_SIZE, firm, firmsize));
        sys.exit(1)

if firmsize != NB_TOTAL_SIZE:
        print 'This program expects a full image of %d bytes (CFE + MAIN + JFFS2 + RESCUE + DSL + NV)' % (NB_TOTAL_SIZE,)
        print 'Your image has a size of %d bytes' % (firmsize)
        ch = raw_input('Continue anyway ? (if you do not know what you do, do not continue !) (y|N) ')
        if ch != 'y':
               sys.exit(0)

print '+++++++++++++++++++++++++++++++++++++++++++++++'
print ' Image: %s' % (firm)
print ' > Size: %d bytes' % (firmsize,)
print '+++++++++++++++++++++++++++++++++++++++++++++++'

# open socket RAW
try:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
except Exception, e:
        sys.stderr.write("Error while creating socket: %s\n" % str(e))
        sys.exit(1)

# bind on device
s.bind((dev,0x8888))

# get the mac addr
my_eth_addr_r = s.getsockname()[-1]

print "%s ethernet address: %s" % (dev, eth_ntoa(my_eth_addr_r))

# write and read packet
dlcpkt_w = Dlcpkt()
dlcpkt_r = Dlcpkt()

# first send discover to get MAC ADDR
# and VERSION_INFO of the box
print " > Info request on broadcast"

dlcpkt_w.dstaddr = ETH_ADDR_BROADCAST
dlcpkt_w.srcaddr = my_eth_addr_r
dlcpkt_w.wcmd = i16ton(CMD_VERSION)

resp = request(s, dlcpkt_w)
dlcpkt_r.unpack(resp)

print " < Receive response from %s - %s" % (eth_ntoa(dlcpkt_r.srcaddr), dlcpkt_r.bdata[4:])

box_eth_addr_r = dlcpkt_r.srcaddr

ch = raw_input('Continue ? (y|N) ')
if ch != 'y':
        print "Ok, exit !"
        s.close()
        sys.exit(0)

# ask we want to put a firmware
print " > Flash request to %s" % (eth_ntoa(box_eth_addr_r))

dlcpkt_w.dstaddr = box_eth_addr_r
dlcpkt_w.wcmd = i16ton(CMD_REQUEST)
dlcpkt_w.wsequence = i16ton(counter_wsequence)

resp = request(s, dlcpkt_w)
dlcpkt_r.unpack(resp)

if dlcpkt_r.wcmd == i16ton(CMD_REQUEST) \
            and dlcpkt_r.wsequence == dlcpkt_w.wsequence :
        print " < Ok, box wait flashing"
else:
        print " < Error on flash request ..."
        s.close()
        sys.exit(0)

counter_wsequence = (counter_wsequence + 1) % (0x10000)

# send the firmware
send_file(s, dlcpkt_w, firm);

dlcpkt_w.bzero()
dlcpkt_w.dstaddr = box_eth_addr_r
dlcpkt_w.srcaddr = my_eth_addr_r

# verify ?

# reboot the box ?
ch = raw_input('Press Enter to reboot the box')
print " > Send reboot request"
        
dlcpkt_w.wcmd = i16ton(CMD_RESET)
resp = request(s, dlcpkt_w);
dlcpkt_r.unpack(resp)

if dlcpkt_r.wcmd == i16ton(CMD_RESET):
        print " < Ok, rebooting the box"
else:
        print " > Error on rebooting command"
        
print "End."

s.close()
