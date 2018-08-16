import os.path

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization

from .hsm_abc import HSM


class EmulatedHSM(HSM):

	def __init__(self, directory):
		self.Directory = directory
		self._PrivateKey = None


	def load(self):
		try:
			self._PrivateKey = cryptography.hazmat.primitives.serialization.load_der_private_key(
				open(os.path.join(self.Directory, 'itss.key'),'rb').read(),
				password=b'strong-and-secret :-)',
				backend=cryptography.hazmat.backends.default_backend()
			)
		except:
			return False
		return True


	def store(self):
		x = self._PrivateKey.private_bytes(
			encoding=cryptography.hazmat.primitives.serialization.Encoding.DER,
			format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
			encryption_algorithm=cryptography.hazmat.primitives.serialization.BestAvailableEncryption(b'strong-and-secret :-)')
		)
		open(os.path.join(self.Directory, 'itss.key'),'wb').write(x)


	def generate_private_key(self):
		self._PrivateKey = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
			cryptography.hazmat.backends.default_backend()
		)


	def get_public_key(self):
		return self._PrivateKey.public_key()


	def sign(self, payload):
		signature_RFC3279 = self._PrivateKey.sign(
			payload,
			cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
				cryptography.hazmat.primitives.hashes.SHA256()
			)
		)
		r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(signature_RFC3279)
		return r, s
