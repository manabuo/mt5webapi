from datetime import datetime as dt
import math

from .api import *

from logging import getLogger
log = getLogger(__name__)


class ApiFacade(object):
	"""
	Facade provides common operations for trading platform.
	"""
	def account_update(self, account):
		"""
		Update trading account on the server.
		"""

	def account_group(self, account):
		"""
		Determine trading account group.
		"""

	def account_change_password(self, account, password):
		"""
		Change trading account password.
		"""

	def account_change_leverage(self, account, leverage):
		"""
		Change trading account leverage.
		"""

	def account_block(self, account):
		"""
		Block a trading account.
		"""

	def account_unblock(self, account):
		"""
		Unblock a trading account.
		"""

	def account_agents(self, account):
		pass

	def account_leverage(self, account):
		"""
		Get trading account leverage.
		"""

	def account_balance(self, account):
		"""
		Get trading account balance.
		"""

	def account_equity(self, account):
		"""
		Get trading account equity.
		"""

	def account_available_leverages(self, account):
		"""
		Get trading account available leverages.
		"""

	def account_trades(self, account, **kwargs):
		"""
		Get trading account trades.
		"""

	def account_deferred_trades(self, account):
		pass

	def account_create(self, account):
		"""
		Create a trading account on the server.
		"""

	def account_deposit(self, account, amount, **kwargs):
		"""
		Deposit money on a trading acc.
		"""

	def account_withdraw(self, account, amount, **kwargs):
		"""
		Withdraw money from a trading acc.
		"""
