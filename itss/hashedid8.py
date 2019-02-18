import struct
import hashlib
import logging

from .enums import EccPointType, PublicKeyAlgorithm

#

L = logging.getLogger(__name__)

#

async def get_pubkey_by_HashedId8(app, hashedid8):
	'''
	Raises exception in case of error
	'''
	cmobj = await app.Storage.get_by("cm", 'cits_hashedid8', hashedid8.hex())
	
	typecls = app.ModelTypes.get(cmobj.get('type', '?'))
	cert = await typecls.load(cmobj['_data'])

	return cert.public_key()


def compute_HashedId8(certificate):
	'''
	Defined in ETSI TS 103 097 V1.2.1 (section 4.2.12)

	HashedId8 is used to identify data such as a certificate.

	It shall be calculated by first computing the SHA-256 hash of the input data,
	and then taking the least significant eight bytes from the hash output.

	A canonical encoding for the EccPoint R contained in the signature field of a ECDSA Certificate
	shall be used when calculating the SHA-256 hash from a Certificate.
	This canonical encoding shall temporarily replace the value of the EccPointType of the 
	point R of the Certificate with x_coordinate_only for the hash computation.

	Usage:

	HashedId8 = compute_HashedId8(certificate)

	'''

	# Strip a signature from a certificate data
	canonical_cert_bytes = certificate.Data[:certificate.SignaturePosition]

	# Add a signature algorithm
	assert(certificate.Signature['algorithm'] == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
	canonical_cert_bytes += struct.pack(">B", certificate.Signature['algorithm'])

	# Add a signature EcdsaSignature 
	r_x = certificate.Signature['ecdsa_signature']['R']['x']
	canonical_cert_bytes += struct.pack(">B", EccPointType.x_coordinate_only) + r_x.to_bytes(32, 'big')
	canonical_cert_bytes += certificate.Signature['ecdsa_signature']['s']

	# Calculate a SHA-256 hash from the whole certificate
	m = hashlib.sha256()
	m.update(canonical_cert_bytes)
	hashed = m.digest()

	# HashedId8 takes the least significant eight bytes
	return(hashed[-8:])
