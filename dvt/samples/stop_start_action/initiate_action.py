# -*- coding: utf-8 -*-
#***************************************************************************
# Copyright (c) 2012 Digi International Inc.
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
#
# ***************************************************************************
# device_request.py
# Send SCI device_request to server. 
# -------------------------------------------------
# Usage: device_request.py <username> <password> <device_id>
# -------------------------------------------------
import httplib
import base64
import sys

def Usage():
    print 'Usage: initial_action.py <username> <password> <device_id> <target> <TCP, UDP, or SMS>\n'
   
def PostMessage(username, password, device_id, target, data):
#    input_file = 'dvt/cases/test_files/pattern.txt'
    input_file = '../../cases/test_files/pattern.txt'

    if data == "none":
        f = open(input_file, 'rb')
        content = f.read()
        f.close()
    else:
        content = data
        
          
    # create HTTP basic authentication string, this consists of
    # "username:password" base64 encoded
    auth = base64.encodestring("%s:%s"%(username,password))[:-1]
    
    # device request message to send to server
    message = """<sci_request version="1.0">
        <data_service>
            <targets>
                <device id="%s"/>
            </targets>
            <requests>
            <device_request target_name="%s">%s</device_request>
            </requests>
        </data_service>
    </sci_request>
    """%(device_id, target, content)
 
    print message
    print "content size %d" % len(content);

    # to what URL to send the request with a given HTTP method
    webservice = httplib.HTTP("test.idigi.com",80)
    webservice.putrequest("POST", "/ws/sci")
    
    # add the authorization string into the HTTP header
    webservice.putheader("Authorization", "Basic %s"%auth)
    webservice.putheader("Content-type", "text/xml; charset=\"UTF-8\"")
    webservice.putheader("Content-length", "%d" % len(message))
    webservice.endheaders()
    webservice.send(message)
    
    # get the response
    statuscode, statusmessage, header = webservice.getreply()
    response_body = webservice.getfile().read()
    
    # print the output to standard out
    if statuscode == 200:
        print '\nResponse:'
        print response_body
    else:
        print '\nError: %d %s' %(statuscode, statusmessage)
    
    webservice.close()


def main(argv):
    #process arguments
    count = len(argv);
    if count != 5:
        Usage()
    else:
        PostMessage(argv[0], argv[1], argv[2], argv[3], argv[4])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
    
