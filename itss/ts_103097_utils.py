import struct

import cryptography.utils

from .enums import *

def parse_var_length_vectors_with_variable_length_encoding(fi):
	'''
	Variable-length vectors with variable-length length encoding
	'''
	b = ord(fi.read(1))
	length = b
	addoct = 0
	for x in range(7,-1, -1):
		if b & (1<<x) == 0:
			length = b & ((1<<x)-1)
			break
		addoct += 1
	for _ in range(addoct):
		length = (length << 8) | ord(fi.read(1))
	return fi.read(length)


def parse_EcdsaSignature(fi, algorithm:PublicKeyAlgorithm):
	field_size = algorithm.field_size()
	ecdsa_signature = {
		#'algorithm': algorithm, - extern
		#'field_size': field_size, - extern
	}
	ecdsa_signature['R'] = parse_EccPoint(fi, algorithm)
	ecdsa_signature['s'] =  fi.read(field_size)
	return ecdsa_signature


def parse_EccPoint(fi, algorithm:PublicKeyAlgorithm):

	field_size = algorithm.field_size()

	eccpoint_type = EccPointType.parse(fi)
	eccpoint_x = fi.read(field_size)
	eccpoint = {
		#'algorithm': algorithm, - extern
		#'field_size': field_size, - extern
		'type': eccpoint_type,
		'x': cryptography.utils.int_from_bytes(eccpoint_x, "big"),
	}

	if eccpoint_type == EccPointType.x_coordinate_only:
		pass

	elif eccpoint_type == EccPointType.compressed_lsb_y_0:
		pass

	elif eccpoint_type == EccPointType.compressed_lsb_y_1:
		pass

	elif eccpoint_type == EccPointType.uncompressed:
		eccpoint_y = fi.read(field_size)
		eccpoint['y'] = cryptography.utils.int_from_bytes(eccpoint_y, "big")

	else:
		raise NotImplementedError("eccpoint_type={}".format(eccpoint_type))

	return eccpoint


def parse_PublicKey(fi):
	public_key_algorithm = PublicKeyAlgorithm.parse(fi)
	public_key = {
		'algorithm': public_key_algorithm,
	}

	if public_key_algorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256:
		public_key['public_key'] = parse_EccPoint(fi, public_key_algorithm)

	elif public_key_algorithm == PublicKeyAlgorithm.ecies_nistp256:
		public_key['supported_symm_alg'] = SymmetricAlgorithm.parse(fi)
		public_key['public_key'] = parse_EccPoint(fi, public_key_algorithm)

	else:
		raise NotImplementedError("public_key.algorithm={}".format(public_key_algorithm))

	return public_key

#

def build_var_length_vectors_with_variable_length_encoding(data):
	'''
	Variable-length vectors with variable-length length encoding
	'''

	if isinstance(data, str):
		data = data.encode('ascii')
	data_len = len(data)

	enc = data_len.to_bytes(7, 'big').lstrip(b'\x00')

	if len(enc) == 0:
		return struct.pack(">B", 0)

	# The maximum length shall be 256 - 1, i.e. at most seven "1"
	bits = len(enc) - 1
	assert(bits <= 7)

	if (127 >> bits) >= enc[0]:
		# We can merge mask into a fist byte
		enc = (((255 >> bits) ^ 0xff) | enc[0]).to_bytes(1, 'big') + enc[1:]
	else:
		# Extra byte is needed
		bits += 1
		assert(bits <= 7)
		enc = ((255 >> bits) ^ 0xff).to_bytes(1, 'big') + enc

	return enc + data


def build_EccPoint_x_coordinate_only(x, field_size=32):
	return struct.pack(">B", EccPointType.x_coordinate_only) \
		+ x.to_bytes(field_size, 'big')


def build_EccPoint_uncompressed(x, y, field_size=32):
	return struct.pack(">B", EccPointType.uncompressed) \
		+ x.to_bytes(field_size, 'big') \
		+ y.to_bytes(field_size, 'big')


def build_PublicKey_ecdsa(pubkey):
	assert(isinstance(pubkey, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey))

	pn = pubkey.public_numbers()
	assert(isinstance(pn.curve, cryptography.hazmat.primitives.asymmetric.ec.SECP256R1))

	return struct.pack(">B", PublicKeyAlgorithm.ecdsa_nistp256_with_sha256) + \
		build_EccPoint_uncompressed(pn.x, pn.y, PublicKeyAlgorithm.ecdsa_nistp256_with_sha256.field_size())
