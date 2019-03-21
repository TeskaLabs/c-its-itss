import PyKCS11

import cryptography.hazmat.primitives.serialization

from .hsm_abc import HSM

class PKCS11HSM(HSM):

	def __init__(self):
		self._privateKey = None
		self._pkcs11 = PyKCS11.PyKCS11Lib()
		self._pkcs11.load(pkcs11dll_filename="/Applications/YubiKey PIV Manager.app/Contents/MacOS/libykcs11.1.dylib")
		self._session = None


	def close(self):
		if self._session is None:
			self._session.logout()
			self._session.closeSession()


	def generate_private_key(self):
		print("Not implemented yet!")


	def load(self):
		self._slot = self._pkcs11.getSlotList(tokenPresent=True)[0]
		self._session = self._pkcs11.openSession(self._slot, PyKCS11.CKF_SERIAL_SESSION)
		self._session.login("11223344")

		self._publicKey = self._session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]
		self._privateKey = self._session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]

		return True


	def get_public_key(self):
		
		ec_point = self._session.getAttributeValue(self._publicKey, [PyKCS11.CKA_EC_POINT])[0]
		assert(ec_point[0] == 0x04) # OCTEC STRING
		assert(ec_point[1] == 0x41) # Length 64+1 bytes
		assert(ec_point[2] == 0x04) # Uncompresses

		public_key_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
			int.from_bytes(ec_point[3:32+3], "big"), # X
			int.from_bytes(ec_point[32+3:], "big"),  # Y
			cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
		)

		backend = cryptography.hazmat.backends.default_backend()
		return public_key_numbers.public_key(backend)


	def sign(self, payload):
		rs = self._session.sign(self._privateKey, payload, mecha=PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256, None))
		r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
		return r, s
