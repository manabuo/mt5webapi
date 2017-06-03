from platforms.mt5.api.commands import *

import unittest

class TestCommands(unittest.TestCase):
	
	def test_create_cmd1(self):
		self.assertEquals(create_cmd_packet(1,'AUTH_START',VERSION=458,AGENT='TEST',LOGIN=14), 
							u'005a00010AUTH_START|LOGIN=14|VERSION=458|AGENT=TEST|\r\n')

if __name__ == '__main__':
	unittest.main()