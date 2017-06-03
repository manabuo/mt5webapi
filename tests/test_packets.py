from platforms.mt5.api.packets import *

import unittest

class TestPackets(unittest.TestCase):
	
	def test_make_packet1(self):
		self.assertEquals(make_packet(u'TEST',1), u'000800010TEST')

if __name__ == '__main__':
	unittest.main()