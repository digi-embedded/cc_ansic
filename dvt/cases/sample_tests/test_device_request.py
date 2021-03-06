# -*- coding: utf-8 -*-
import time
import ic_testcase
import datetime
import re
import os
from base64 import b64encode

import xml.dom.minidom
from xml.dom.minidom import getDOMImplementation
impl = getDOMImplementation()

from ..utils import getText

expected_content = "iDigi device request sample [0]\n"


class SendDeviceRequestTestCase(ic_testcase.TestCase):
       
    def test_device_request(self):
    
        """ Verifies that the device request returned match the expected 
        response.
        """
        my_target_name = "myTarget"
        my_target_response = "My device response data"

        my_target_device_request = \
            """<sci_request version="1.0">
              <data_service>
                <targets>
                  <device id="%s"/>
                </targets>
                <requests>
                <device_request target_name="%s">My device request data</device_request>
                </requests>
              </data_service>
            </sci_request>""" % (self.device_id, my_target_name)

        self.log.info("Beginning Test for device request.")
        self.log.info("Sending device request for \"%s\" target_name to server for device id  %s." % (my_target_name, self.device_id))
        
        # Send device request
        device_request_response = self.session.post('http://%s/ws/sci' % self.hostname, data=my_target_device_request)
        self.assertEqual(200, device_request_response.status_code)
        # Parse request response 
        dom = xml.dom.minidom.parseString(device_request_response.content)
        device_response = dom.getElementsByTagName("device_request")
        
        # Validate target name
        self.log.info("Determining if the target_name is \"%s\"." % my_target_name)
        target_name = device_response[0].getAttribute('target_name')
        self.assertEqual(target_name, my_target_name, 
            "returned target (%s) is not (%s)" 
            % (target_name, my_target_name))

        # Validate status 
        self.log.info("Determining if status is success.")
        status = device_response[0].getAttribute("status")
        self.assertEqual(status, '0', 
            "returned status (%s) is not success status" 
            % status)
        
        # Validate response data
        self.log.info("Determining if response data is expected \"%s\"." % my_target_response)
        
        data = device_response[0].firstChild.data
        self.assertEqual(data, my_target_response,
            "returned target (%s) is not (%s)" 
            % (data, my_target_response))

    def test_invalid_target_device_request(self):
    
        """ Verifies that the device request returned match the expected 
        response.
        """
        my_target_name = "invalidTarget"

        my_target_device_request = \
            """<sci_request version="1.0">
              <data_service>
                <targets>
                  <device id="%s"/>
                </targets>
                <requests>
                <device_request target_name="%s">My device request data</device_request>
                </requests>
              </data_service>
            </sci_request>""" % (self.device_id, my_target_name)

        self.log.info("Beginning Test for device request.")
        self.log.info("Sending device request for \"%s\" target_name to server for device id  %s." % (my_target_name, self.device_id))
        
        # Send device request
        device_request_response = self.session.post('http://%s/ws/sci' % self.hostname, data=my_target_device_request)
        self.assertEqual(200, device_request_response.status_code)
        
        # Parse request response 
        dom = xml.dom.minidom.parseString(device_request_response.content)
        device_response = dom.getElementsByTagName("device_request")
        
        # Validate cancel message response
        self.log.info("Determining if \"%s\" target is not handle." % my_target_name)
        
        status = device_response[0].getAttribute("status")
        self.assertEqual(status, '1', 
            "returned status (%s) is not not handled" 
            % status)

if __name__ == '__main__':
    unittest.main() 
