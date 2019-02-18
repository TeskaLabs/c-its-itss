import abc


class HSM(abc.ABC):


	def close(self):
		pass


	def load(self):
		'''
		Load from persistent storage.
		Return True if OK (private key exists) or False if privake key doesn't exists
		'''
		return False


	def store(self):
		'''
		Store to persistent storage. Can be NOOP. 
		'''
		pass


	@abc.abstractmethod
	def generate_private_key(self):
		'''
		Generate a private key.
		'''
		pass


	@abc.abstractmethod
	def get_public_key(self):
		'''
		Get a public key for a private key
		'''
		pass


	@abc.abstractmethod
	def sign(self, payload):
		'''
		Sign a payload, return 'r' and 's'.
		'''
		pass
