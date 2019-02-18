import cryptography.hazmat.backends

from .hsm_abc import HSM

class CicadaHSM(HSM):

	def __init__(self):
		self._PrivateKey = None
		self.P11URI = None

		self.Label = "test-key"

		backend = cryptography.hazmat.backends.default_backend()
		backend._lib.ENGINE_load_dynamic()
		engine = backend._lib.ENGINE_by_id(b"dynamic");
		backend.openssl_assert(engine != backend._ffi.NULL)
		engine = backend._ffi.gc(engine, backend._lib.ENGINE_free)

		backend._lib.ENGINE_ctrl_cmd_string(engine, b"SO_PATH", b"/usr/lib/arm-linux-gnueabihf/engines-1.1/libpkcs11.so", 0)
		backend._lib.ENGINE_ctrl_cmd_string(engine, b"ID", b"pkcs11", 0)
		backend._lib.ENGINE_ctrl_cmd_string(engine, b"LOAD", backend._ffi.NULL, 0)
		backend._lib.ENGINE_ctrl_cmd_string(engine, b"MODULE_PATH", b"/usr/lib/cicada-pkcs11.so", 0)
		res = backend._lib.ENGINE_init(engine)
		backend.openssl_assert(res > 0)

		self.Engine = engine


	def generate_private_key(self):
		'''
		pkcs11-tool --module cicada-pkcs11.so --keypairgen --key-type EC:secp256r1 --label "test-key" --usage-sign
		'''
		print("Not implemented yet!")


	def load(self):
		p11uri = "pkcs11:object={};type=private".format(self.Label)
		backend = cryptography.hazmat.backends.default_backend()
		pkey = backend._lib.ENGINE_load_private_key(
			self.Engine,
			p11uri.encode("utf-8"),
			backend._ffi.NULL,
			backend._ffi.NULL
		)

		backend.openssl_assert(pkey != backend._ffi.NULL)
		pkey = backend._ffi.gc(pkey, backend._lib.EVP_PKEY_free)
		self.P11URI = p11uri
		self._PrivateKey = backend._evp_pkey_to_private_key(pkey)


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
