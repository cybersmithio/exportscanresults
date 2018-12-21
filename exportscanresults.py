#!/usr/bin/python3
#
# Takes scan results from Tenable.io or Tenable.sc and outputs them to a file
#
# Version 0.9 - Just does tenable.io for now
#
#
# Example usage with environment variables:
# export TIO_ACCESS_KEY="********************"
# export TIO_SECRET_KEY="********************"
# python3 ./exportscanresults.py --outfile output.pdf --scanname "Tenable SE Lab basic scan" --tiofilter "[('severity', 'eq', 'Critical'),('plugin.attributes.in_the_news', 'eq', 'true')]" --format pdf
#
# Requires the following:
#   pip install pytenable ipaddr netaddr

import json
import os
import csv
import sys
import time
from tenable.io import TenableIO
import argparse
import netaddr
import ipaddr
from ast import literal_eval

def GetScanID(DEBUG,tio,scanname):
    if DEBUG:
        print("Searching for scan with name: "+str(scanname))
    scanid=False
    for scan in tio.scans.list():
        if DEBUG:
            print("Scan: ",scan)
        if scan['name'] == str(scanname):
            if DEBUG:
                print("Found scan name "+str(scanname)+" with ID "+str(scan['id']))
            scanid=int(scan['id'])
    return(scanid)


#Right now, host and port are ignored
def DownloadScanResults(DEBUG,accesskey,secretkey,host,port,scanname,tiofilter,outfile,format):
    #Create the connection to Tenable.io
    tio=TenableIO(accesskey, secretkey)

    scanid=GetScanID(DEBUG,tio,scanname)
    if not scanid:
        print("Could not find scan name")
        return(False)

    if DEBUG:
        print("Found scan ID:",str(scanid))

    if tiofilter != "":
        filter=literal_eval(tiofilter)
    else:
        filter=[]

    #Export the scan results
    if DEBUG:
        print("Filtering by the following JSON:",filter)

    #Write to a file
    fpout=open(outfile,"wb")
    tio.scans.export(scanid,  *filter, chapters=["vuln_by_host"], format=format, fobj=fpout)
    fpout.close()

    return(True)




######################
###
### Program start
###
######################

# Get the arguments from the command line
parser = argparse.ArgumentParser(description="Pulls the scan results from Tenable.io or Tenable.sc, and exports into a file")
parser.add_argument('--scanname',help="The name of the scan to export.  (If there are duplicate names then it takes the last matching one)",nargs=1,action="store",required=True)
parser.add_argument('--outfile',help="The name of the file to write.",nargs=1,action="store",required=True)
parser.add_argument('--format',help="The format of the output. Values are: csv, pdf, html, db, nessus. The default is csv",nargs=1,action="store")
parser.add_argument('--tiofilter',help="A JSON filter string written in the format Tenable.io expects. See https://cloud.tenable.com/api#/resources/scans/export-request",nargs=1,action="store")
parser.add_argument('--accesskey',help="The Tenable.io access key",nargs=1,action="store")
parser.add_argument('--secretkey',help="The Tenable.io secret key",nargs=1,action="store")
parser.add_argument('--host',help="The Tenable.io host. (Default is cloud.tenable.com)",nargs=1,action="store")
parser.add_argument('--port',help="The Tenable.io port. (Default is 443)",nargs=1,action="store")
parser.add_argument('--debug',help="Turn on debugging",action="store_true")

args=parser.parse_args()

DEBUG=False

if args.debug:
    DEBUG=True
    print("Debugging is enabled.")



# Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('TIO_ACCESS_KEY') is None:
    accesskey = ""
else:
    accesskey = os.getenv('TIO_ACCESS_KEY')

# If there is an access key specified on the command line, this override anything else.
try:
    if args.accesskey[0] != "":
        accesskey = args.accesskey[0]
except:
    nop = 0


if os.getenv('TIO_SECRET_KEY') is None:
    secretkey = ""
else:
    secretkey = os.getenv('TIO_SECRET_KEY')


# If there is an  secret key specified on the command line, this override anything else.
try:
    if args.secretkey[0] != "":
        secretkey = args.secretkey[0]
except:
    nop = 0

try:
    if args.host[0] != "":
        host = args.host[0]
except:
    host = "cloud.tenable.com"

try:
    if args.port[0] != "":
        port = args.port[0]
except:
    port = "443"

try:
    if args.scanname[0] != "":
        scanname=args.scanname[0]
except:
    scanname=""

try:
    if args.tiofilter[0] != "":
        tiofilter=args.tiofilter[0]
except:
    tiofilter=""


try:
    if args.outfile[0] != "":
        outfile=args.outfile[0]
except:
    outfile=""

try:
    if args.format[0] != "":
        format=args.format[0]
except:
    format="csv"

if (format != "csv") and (format != "html") and (format != "pdf") and (format != "db") and (format != "nessus"):
    print("Invalid format.")

print("Connecting to cloud.tenable.com with access key",accesskey,"to report on assets")

DownloadScanResults(DEBUG,accesskey,secretkey,host,port,scanname,tiofilter,outfile,format)


