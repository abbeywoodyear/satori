from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer12 import linuxcc
from pypacker.layer3 import ip
from pypacker.layer3 import icmp
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker.layer567 import dhcp
from pypacker.layer567 import http
from pypacker import pypacker
from datetime import datetime
import pcapy
import getopt
import time
import sys
import os
import signal
import satoriTCP
import satoriDHCP
import satoriHTTP
#import satoriICMP
import satoriSMB
#import smb
import logging
import logging.config

def usage():
    print("""
    -d, --directory   directory to read all pcaps in one at a time; example -d /pcaps
    -r, --read        pcap to read in; example: -r tcp.pcap
    -i, --interface   interface to listen to; example: -i eth0
    -m, --modules     modules to load; example: -m tcp,dhcp
    -l, --log         log file to write output to; example -l output.txt (not implemented yet)
    -v, --verbose     verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically
    """, end='\n', flush=True)


def packetType(buf):
  tcpPacket = False
  dhcpPacket = False
  httpPacket = False
  udpPacket = False

  #try to determine what type of packets we have, there is the chance that 0x800 may be in the spot we're checking, may want to add better testing in future
  eth = ethernet.Ethernet(buf)
  if hex(eth.type) == '0x800':
    layer = 'eth'
    pkt = eth

    if (eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None):
      tcpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, udp.UDP, dhcp.DHCP] is not None):
      dhcpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP] is not None):
      httpPacket = True
    if (eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None):
      udpPacket = True

  lcc = linuxcc.LinuxCC(buf)
  if hex(lcc.type) == '0x800':
    layer = 'lcc'
    pkt = lcc

    if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP] is not None):
      tcpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dhcp.DHCP] is not None):
      dhcpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, http.HTTP] is not None):
      httpPacket = True
    if (lcc[linuxcc.LinuxCC, ip.IP, udp.UDP] is not None):
      udpPacket = True

  return(pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket)


def main():
  #override some warning settings in pypacker.  May need to change this to .CRITICAL in the future, but for now we're trying .ERROR
  #without this when parsing http for example we get "WARNINGS" when packets aren't quite right in the header.
  pyplogger = pypacker.logging.getLogger("pypacker")
  pyplogger.setLevel(pypacker.logging.ERROR)

  # initialises logger, will output only ERROR logs and above if log command argument not set
  console_handler = logging.StreamHandler()
  console_handler.setLevel(logging.INFO)
  if not log:
    console_handler.setLevel(logging.INFO)
  else:
    logger.info(f"\n{datetime.now()}")
    console_handler.setLevel(logging.ERROR)
  console_formatter = logging.Formatter('%(message)s')
  console_handler.setFormatter(console_formatter)
  logger.addHandler(console_handler)

  counter = 0
  startTime = time.time()

  tcpCheck = False
  dhcpCheck = False
  httpCheck = False
  icmpCheck = False  #not enabled in lower code at this point due to tracking features I'm not willing to code at this time.
  smbCheck = False

  #read in fingerprints
  [sExactList, saExactList, sPartialList, saPartialList] = satoriTCP.BuildTCPFingerprintFiles()
  [DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, DeclineTTLExactList] = satoriDHCP.BuildDHCPFingerprintFiles()
  [useragentExactList, useragentPartialList] = satoriHTTP.BuildHTTPUserAgentFingerprintFiles()
  [serverExactList, serverPartialList] = satoriHTTP.BuildHTTPServerFingerprintFiles()
  #[icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList] = satoriICMP.BuildICMPFingerprintFiles()
  [nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList] = satoriSMB.BuildSMBTCPFingerprintFiles()
  [browserExactList, browserPartialList] = satoriSMB.BuildSMBUDPFingerprintFiles()

  if len(modules) == 0:
    #no preference so we'll run all modules we have
    tcpCheck = True
    dhcpCheck = True
    httpCheck = True
    icmpCheck = True
    smbCheck = True
  else:
    #requested a specific one, so lets only enable what was asked for
    mod = modules.split(',')
    for i in range(len(mod)):
      if (mod[i].lower() == 'tcp'):
        tcpCheck = True
      elif (mod[i].lower() == 'dhcp'):
        dhcpCheck = True
      elif (mod[i].lower() == 'http'):
        httpCheck = True
      elif (mod[i].lower() == 'icmp'):
        icmpCheck = True
      elif (mod[i].lower() == 'smb'):
        smbCheck = True

  if (directory != ''):  #probably a better way to do this and dupe most of the below code from preader section, but DHCP passing parameters into a procedure sucks.
    onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    for f in onlyfiles:
      #print(f, end='\n', flush=True)
      try:
        preader = ppcap.Reader(filename=directory + '/' + f)
        for ts, buf in preader:
          try:
            counter = counter + 1
            ts = ts/1000000000

            (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)

            if tcpPacket and tcpCheck:
              satoriTCP.tcpProcess(pkt, layer, ts, sExactList, saExactList, sPartialList, saPartialList)
            if dhcpPacket and dhcpCheck:
              satoriDHCP.dhcpProcess(pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                     ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                     InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                     ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                     AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                     RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                     ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                     DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                     AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                     NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                     OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                     OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                     DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                     DeclineTTLExactList)
            if httpPacket and httpCheck:
              satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
              satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
#            if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#              satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
            if tcpPacket and smbCheck:
              satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
            if udpPacket and smbCheck:
              satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
          except (KeyboardInterrupt, SystemExit):
            raise
          except:
            pass
      except:
        pass
#        print('File was not pcap format')
#        sys.exit(1)


  elif (readpcap != ''):
    try:
      preader = ppcap.Reader(filename=readpcap)
    except:
      logger.error('File was not pcap format')
      sys.exit(1)
    for ts, buf in preader:
      try:
        counter = counter + 1
        ts = ts/1000000000

        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)

        if tcpPacket and tcpCheck:
          satoriTCP.tcpProcess(pkt, layer, ts, sExactList, saExactList, sPartialList, saPartialList)
        if dhcpPacket and dhcpCheck:
          satoriDHCP.dhcpProcess(pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                 ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                 InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                 ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                 AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                 RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                 ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                 DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                 AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                 NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                 OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                 OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                 DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                 DeclineTTLExactList)
        if httpPacket and httpCheck:
          satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
          satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
#        if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#          satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
        if tcpPacket and smbCheck:
          satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
        if udpPacket and smbCheck:
          satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)

      except (KeyboardInterrupt, SystemExit):
        raise
      except:
        pass


  elif interface != '':
    try:
      preader = pcapy.open_live(interface, 65536, False, 1)
      #highly recommended to add something like this for a bpf filter on a high throughput connection (4 Gb/s link script sorta died on me in testing)
      #assuming only doing -m http
      #preader.setfilter('tcp port 80 or tcp port 8080')
    except Exception as e:
      logger.exception(e)
      sys.exit(1)
    while True:
      try:
        counter = counter + 1
        (header, buf) = preader.next()
        ts = header.getts()[0]

        (pkt, layer, tcpPacket, dhcpPacket, httpPacket, udpPacket) = packetType(buf)

        if tcpPacket and tcpCheck:
          satoriTCP.tcpProcess(pkt, layer, ts, sExactList, saExactList, sPartialList, saPartialList)
        if dhcpPacket and dhcpCheck:
          satoriDHCP.dhcpProcess(pkt, layer, ts, DiscoverOptionsExactList, DiscoverOptionsPartialList, RequestOptionsExactList, RequestOptionsPartialList, ReleaseOptionsExactList, 
                                 ReleaseOptionsPartialList, ACKOptionsExactList, ACKOptionsPartialList, AnyOptionsExactList, AnyOptionsPartialList, InformOptionsExactList, 
                                 InformOptionsPartialList, DiscoverOption55ExactList, DiscoverOption55PartialList, RequestOption55ExactList, RequestOption55PartialList, 
                                 ReleaseOption55ExactList, ReleaseOption55PartialList, ACKOption55ExactList, ACKOption55PartialList, AnyOption55ExactList, 
                                 AnyOption55PartialList, InformOption55ExactList, InformOption55PartialList, DiscoverVendorCodeExactList, DiscoverVendorCodePartialList, 
                                 RequestVendorCodeExactList, RequestVendorCodePartialList, ReleaseVendorCodeExactList, ReleaseVendorCodePartialList, ACKVendorCodeExactList, 
                                 ACKVendorCodePartialList, AnyVendorCodeExactList, AnyVendorCodePartialList, InformVendorCodeExactList, InformVendorCodePartialList, 
                                 DiscoverTTLExactList, DiscoverTTLPartialList, RequestTTLExactList, RequestTTLPartialList, ReleaseTTLExactList, ACKTTLExactList, 
                                 AnyTTLExactList, InformTTLExactList, ACKTTLPartialList, AnyTTLPartialList, InformTTLPartialList, NAKOptionsPartialList, NAKOptionsExactList, 
                                 NAKOption55PartialList, NAKOption55ExactList, NAKVendorCodePartialList, NAKVendorCodeExactList, NAKTTLPartialList, NAKTTLExactList, 
                                 OfferOptionsPartialList, OfferOptionsExactList, OfferOption55PartialList, OfferOption55ExactList, OfferVendorCodePartialList, 
                                 OfferVendorCodeExactList, OfferTTLPartialList, OfferTTLExactList, DeclineOptionsPartialList, DeclineOptionsExactList, 
                                 DeclineOption55PartialList, DeclineOption55ExactList, DeclineVendorCodePartialList, DeclineVendorCodeExactList, DeclineTTLPartialList, 
                                 DeclineTTLExactList)
        if httpPacket and httpCheck:
          satoriHTTP.httpUserAgentProcess(pkt, layer, ts, useragentExactList, useragentPartialList)
          satoriHTTP.httpServerProcess(pkt, layer, ts, serverExactList, serverPartialList)
#        if (eth[ethernet.Ethernet, ip.IP, icmp.ICMP] is not None) and icmpCheck:
#          satoriICMP.icmpProcess(eth, ts, icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList)
        if tcpPacket and smbCheck:
          satoriSMB.smbTCPProcess(pkt, layer, ts, nativeExactList, lanmanExactList, nativePartialList, lanmanPartialList)
        if udpPacket and smbCheck:
          satoriSMB.smbUDPProcess(pkt, layer, ts, browserExactList, browserPartialList)
      except (KeyboardInterrupt, SystemExit):
        raise
      except:
        pass


  else:  #we should never get here with "proceed" check, but just in case
    logger.info("Not sure how we got here", end='\n', flush=True)

  endTime = time.time()
  totalTime = endTime - startTime

  if verbose:
    logger.info('Total Time: %s, Total Packets: %s, Packets/s: %s' % (totalTime, counter, counter / totalTime ))

try:
  opts, args = getopt.getopt(sys.argv[1:], "r:m:i:l:vd:", [ 'read=', 'modules=', 'interface=', 'log=', 'verbose', 'directory='])

  readpcap = interface = modules = log = directory = ''
  proceed = False
  verbose = False

  #need to eventually do a check to make sure both readpcap and interface are not both set!
  for opt, val in opts:
    logger = logging.getLogger(__name__) # to allow for error logs from command args
    logger.setLevel(logging.INFO)
    if opt in ('-r', '--read'):
      if not os.path.isfile(val):
        logger.error('\nFile "%s" does not appear to exist, please verify pcap file name.' % val)
        sys.exit()
      else:
        proceed = True
        readpcap = val
    if opt in ('-m', '--modules'):
      modules = val
    if opt in ('-i', '--interface'):
      interface = val
      proceed = True
    if opt in ('-l', '--log'):  #auto-appends logging information if file exists
      log = val
      file_handler = logging.FileHandler(val)
      file_handler.setLevel(logging.INFO)
      file_formatter = logging.Formatter('%(message)s')
      file_handler.setFormatter(file_formatter)
      logger.addHandler(file_handler)
    if opt in ('-v', '--verbose'):
      verbose = True
    if opt in ('-d', '--directory'):
      if not os.path.isdir(val):
        logger.error('\nDir "%s" does not appear to exist, please verify directory name.' % val)
        sys.exit()
      else:
        proceed = True
        directory = val

  if (__name__ == '__main__') and proceed:
    main()
  else:
    # logger.error('\nNeed to provide a pcap to read in or an interface to watch')
    usage()

except getopt.error:
     usage()



