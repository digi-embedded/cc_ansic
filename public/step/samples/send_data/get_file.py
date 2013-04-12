# ***************************************************************************
# Copyright (c) 2012 Digi International Inc.,
# All rights not expressly granted are reserved.
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# 
# Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
#
# ***************************************************************************
# get_file.py
# Get a file from Etherios Device Cloud storage
# -------------------------------------------------
# Usage: get_file.py <username> <password> <device_id>
# -------------------------------------------------

import httplib
import base64
import sys
import re

def Usage():
    print 'Usage: get_file.py <username> <password> <device_id>\n'

def GetMessage(username, password, device_id):
    # create HTTP basic authentication string, this consists of
    # "username:password" base64 encoded
    auth = base64.encodestring("%s:%s"%(username,password))[:-1]

    # device request message to send to server
    path = """/ws/FileData/~/%s/test/test.txt"""%(device_id)

    # to what URL to send the request with a given HTTP method
    webservice = httplib.HTTP("login.etherios.com",80)
    webservice.putrequest("GET", path)

    # add the authorization string into the HTTP header
    webservice.putheader("Authorization", "Basic %s"%auth)
    webservice.putheader("Accept", "text/html; charset=\"UTF-8\"")
    #webservice.putheader("Content-length", "%d" % len(message))
    webservice.endheaders()
    #webservice.send(message)

    # get the response
    statuscode, statusmessage, header = webservice.getreply()
    response_body = webservice.getfile().read()

    # print the output to standard out
    if statuscode == 200:
        print response_body
    else:
        print '\nError: %d %s' %(statuscode, statusmessage)

    webservice.close()


def main(argv):
    #process arguments
    count = len(argv);
    if count != 3:
        Usage()
    else:
        if len(argv[2]) == len("12345678-12345678"):
            device_id = "00000000-00000000-" + argv[2]
        else:
            device_id = argv[2]

        if re.match( "([0-9A-Fa-f]{8}-){3}[0-9A-Fa-f]{8}", device_id) == None:
            print 'Error: Invalid device id [%s]' %argv[2]
        else:
            GetMessage(argv[0], argv[1], device_id)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

