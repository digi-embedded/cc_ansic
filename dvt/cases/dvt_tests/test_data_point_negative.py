import time
import ic_testcase
import sys

from utils import DeviceConnectionMonitor

class DataPointNegativeTestCase(ic_testcase.TestCase):
    monitor=None

    def setUp(self):
        ic_testcase.TestCase.setUp(self)
        # Optimization, reuse the DeviceConnectionMonitor to avoid creating
        # multiple sessions over and over.
        if DataPointNegativeTestCase.monitor is None:
            DataPointNegativeTestCase.monitor = DeviceConnectionMonitor(self.push_client, self.dev_id)
            DataPointNegativeTestCase.monitor.start()
        self.monitor = DataPointNegativeTestCase.monitor

    @classmethod
    def tearDownClass(cls):
        if DataPointNegativeTestCase.monitor is not None:
            DataPointNegativeTestCase.monitor.stop()
        ic_testcase.TestCase.tearDownClass()

    def test_dp1_tcp_int(self):
        """ Validate dp_tcp_int stream """
        self.verify_dp_file("dpn_tcp_int")

    def test_dp7_udp_int(self):
        """ Validate dp_udp_int stream """
        self.verify_dp_file("dpn_udp_int")

    def test_dp2_tcp_long(self):
        """ Validate dp_tcp_long stream """
        self.verify_dp_file("dpn_tcp_long")

    def test_dp8_udp_long(self):
        """ Validate dp_udp_long stream """
        self.verify_dp_file("dpn_udp_long")

    def test_dp3_tcp_float(self):
        """ Validate dp_tcp_float stream """
        self.verify_dp_file("dpn_tcp_float")

    def test_dp9_udp_float(self):
        """ Validate dp_udp_float stream """
        self.verify_dp_file("dpn_udp_float")

    def test_dp4_tcp_double(self):
        """ Validate dp_tcp_double stream """
        self.verify_dp_file("dpn_tcp_double")

    def test_dpa_udp_double(self):
        """ Validate dp_udp_double stream """
        self.verify_dp_file("dpn_udp_double")

    def test_dp5_tcp_string(self):
        """ Validate dp_tcp_string stream """
        self.verify_dp_file("dpn_tcp_string")

    def test_dpb_udp_string(self):
        """ Validate dp_udp_string stream """
        self.verify_dp_file("dpn_udp_string")

    def test_dp6_tcp_binary(self):
        """ Validate dp_tcp_binary stream """
        self.verify_dp_file("dpn_tcp_binary")

    def test_dpc_udp_binary(self):
        """ Validate dp_udp_binary stream """
        self.verify_dp_file("dpn_udp_binary")

    def verify_dp_file (self, stream_name):
        retry_count = 10
        stream_path = "DataPoint/%s/%s" % (self.device_id, stream_name)

        self.log.info("Verifying %s..." % stream_name)

        while (retry_count > 0):
            retry_count -= 1
            try:
                dataPoint_response = self.rest_session.get_first(stream_path, params={'order' : 'desc'}, timeout=2000)
                if dataPoint_response.status_code == 200:
                    break
                else:
                    self.log.info("Data response code [%d] for %s, retrying\n" % (dataPoint_response.status_code, stream_name))
            except Exception, e:
                self.log.info("Received Exception for %s, retrying\n" % stream_name)

        if dataPoint_response.status_code == 200:
            data_point  = dataPoint_response.resource
            if stream_name.find('binary') == -1:
                self.log.info("Found %s, %s" % (stream_name, data_point))
                if stream_name.find('string') > 0:
                    self.assertTrue(data_point == None)
            else:
                self.log.info("Found %s, DataPoint: binary data" % stream_name)

            self.log.info("Deleting %s..." % stream_name)
            response = self.rest_session.delete(stream_path)
            self.log.info("Delete response: %s" % response)
        else:
            self.assertTrue(dataPoint_response.status_code == 400 or dataPoint_response.status_code == 500)
            self.log.info("%s is not found and is deleted by the user" % stream_name)

if __name__ == '__main__':
    unittest.main()