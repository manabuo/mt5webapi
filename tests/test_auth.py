from platforms.mt5.api.auth import *
import unittest

class TestAuth(unittest.TestCase):
	def test_srv_rand_answer1(self):
		self.assertEquals(make_auth_answer_hash('Password1', '73007dc7184747ce0f7c98516ef1c851'), 
						u'77fe51827f7fa69dd80fbec9aa33f1bb')

if __name__ == '__main__':
	unittest.main()