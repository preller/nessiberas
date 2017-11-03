# file nessiberas.py

import argparse
import os
import xml.etree.ElementTree as etree
from sets import Set

#import base64

authorSignature =  'TODO SIGNATURE\n'
#authorSignature += '======================================='


### AUX ###
class VulnerableHost(object):
    def __init__(self, hostName):
        self.hostName = hostName
        self.ports = dict()

    def addProtocolPortPair(self, protocol, port):
        if self.ports.get(protocol) == None:
            self.ports[protocol] = set()
        self.ports.get(protocol).add(port)

    def __eq__(self, other):
        if isinstance(other, VulnerableHost):
            return (self.hostName == other.hostName)
        else:
            return False    

    def __hash__(self):
        return hash(self.hostName)

    def printHostName(self):
        print self.hostName

    def printPortsMultiline(self):
        #print self.ports
        for p in self.ports:
            print p + ": "
            for n in self.ports.get(p):
                print n



### /AUX ###


### PLUGIN MODE ###

def printOnePerLine(vulDict):
        for vh in vulDict:
            for proto in vulDict.get(vh).ports:
                for port in vulDict.get(vh).ports.get(proto):
                    print proto + ":" + vh + ":" + port

def pluginidMode(args):
    #print args.level
    #print args.severity

   # print "SET"
    
    #asd = VulnerableHost("123.123.123.123")
    #asd.addProtocolPortPair("tcp", "2")
    #asd.addProtocolPortPair("tcp", "3")
    #asd.addProtocolPortPair("tcp", "2")
    #asd.printHosts()


   # print "/SET"

    vulDict = dict()

    directory = args.directory
    if (args.directory == "DEFAULT"):
        directory = os.getcwd() + "/reports"

   # print "TAGS\n"
    for fileName in os.listdir(directory):
        if ".nessus" in fileName:
            rhosts = etree.parse(directory + '/' + fileName).find('Report').findall('ReportHost')
            for rhost in rhosts:
                ritems = rhost.findall('ReportItem')
                for ritem in ritems:
                    if ritem.get('pluginID') == args.pluginID:
                        # print rhost.get('name')
                        if rhost.get('name') not in vulDict:
                            vulDict.update({rhost.get('name'): VulnerableHost(rhost.get('name'))})
                        currentVulEl = vulDict.get(rhost.get('name'))
                        currentVulEl.addProtocolPortPair(ritem.get('protocol'), ritem.get('port'))


                       # vulSet.get(rhost.get('name')).addProtocolPortPair(ritem.get('protocol'), ritem.get('port'))
                        #print ritem.get('pluginID')
                        #print rhost.get('name')

    #for vh in vulDict:
    #    vulDict.get(vh).printHostName()
    #    vulDict.get(vh).printPortsMultiline()
    printOnePerLine(vulDict)





#    for each nessus file
#        for each reporthost in report 
#            for each reportitem
#                if the plugin is correct
#                    store the host, protocol and port object in the set (hash function is the three values), severity and stuff later
    
#    printVulnerableHosts()


### /PLUGIN MODE ###


### PARSER ###
# Map for clarity's sake
def arg_pluginid_mode(args):
    #print authorSignature
    pluginidMode(args)


# Base parser
parser = argparse.ArgumentParser(description = 'TODO', epilog='--- TODO ------------------', add_help=True)
subparsers = parser.add_subparsers(title='modes', description='valid modes', help='use ... MODE -h for help about specific modes')
parser.add_argument('-d', '--directory', help='reports full path directory (default is ./reports)', default='DEFAULT')

# Grep by pluginID mode
pluginid_subparser = subparsers.add_parser('pluginid', help='TODO')
pluginid_subparser.add_argument("pluginID", help="the target pluginID")
pluginid_subparser.add_argument("-l", "--level", help="information level: 1 (default: 1), 2 (ports)", default=1)
pluginid_subparser.add_argument("-s", "--severity", help="set severity level (default: none)", default="none")
pluginid_subparser.set_defaults(func=arg_pluginid_mode)
    
# Merge reports mode
#TODO

# XLS file creation mode
#TODO



# Store the user args
args = parser.parse_args()
args.func(args) 
### /PARSER ###