import struct
import hashlib
import logging

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


def compute_HashedId8(signature_r_x):
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

	HashedId8 = compute_HashedId8(Signature['ecdsa_signature']['R']['x'])

	'''

	#TODO: This is DER encoding ... likely different from CER encoding, which is required by specifications

	encoded = signature_r_x.to_bytes(32, 'big')
	if (encoded[0] & 0x80) == 0x80:
		encoded = b'\0' + encoded

	encoded = struct.pack(">BB",
		0x81, len(encoded)
	) + encoded

	encoded = struct.pack(">BBBBB",
		0x80, 0x01, 0x00, # x_coordinate_only
		0xA1, len(encoded)
	) + encoded

	# Enclose in the array
	encoded = struct.pack(">BB",
		0x30, len(encoded)
	) + encoded

	m = hashlib.sha256()
	m.update(encoded)
	hashed = m.digest()

	return(hashed[-8:])
