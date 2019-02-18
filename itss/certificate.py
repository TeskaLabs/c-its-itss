import io
import hashlib

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.backends
import cryptography.hazmat.backends.openssl.ec

from .hashedid8 import compute_HashedId8, get_pubkey_by_HashedId8
from .ts_103097_utils import *
from .enums import *

class CITS103097v121Certificate(object):
	'''
	ETSI TS 103 097 V1.2.1
	'''

	def __init__(self, data:bytes):
		self.Data = data
		fi = io.BytesIO(data)

		self.Version = ord(fi.read(1))
		self.SignerInfo = parse_SignerInfo(fi)

		# SubjectInfo
		subject_type = SubjectType.parse(fi)
		subject_name = parse_var_length_vectors_with_variable_length_encoding(fi)
		self.SubjectInfo = {
			'subject_type': subject_type,
			'subject_name': subject_name.decode('ascii'),
		}

		# SubjectAttribute
		self.SubjectAttributes = []
		subject_attributes = parse_var_length_vectors_with_variable_length_encoding(fi)
		fia = io.BytesIO(subject_attributes)
		while True:
			sa = {}
			subject_attribute_type = fia.read(1)
			if len(subject_attribute_type) == 0: break

			subject_attribute_type = SubjectAttributeType(ord(subject_attribute_type))
			sa['type'] = subject_attribute_type
			unique_check = [sai for sai in self.SubjectAttributes if sai['type'] == subject_attribute_type]
			assert(len(unique_check) == 0)
			
			if     (subject_attribute_type == SubjectAttributeType.verification_key) \
				or (subject_attribute_type == SubjectAttributeType.encryption_key):
				public_key = parse_PublicKey(fia)
				sa['public_key'] = public_key
			
			elif subject_attribute_type == SubjectAttributeType.assurance_level:
				sa['assurance_level'] = ord(fia.read(1)) # read `opaque SubjectAssurance`
			
			elif subject_attribute_type == SubjectAttributeType.its_aid_list:
				its_aid_list = parse_var_length_vectors_with_variable_length_encoding(fia)
				sa['its_aid_list'] = [x for x in its_aid_list]

			elif subject_attribute_type == SubjectAttributeType.its_aid_ssp_list:
				its_aid_ssp_list = parse_var_length_vectors_with_variable_length_encoding(fia)
				sa['its_aid_ssp_list'] = its_aid_ssp_list
			
			else:
				raise NotImplementedError("subject_attributes.type={}".format(subject_attribute_type))
			
			self.SubjectAttributes.append(sa)


		# ValidityRestriction
		validity_restrictions = parse_var_length_vectors_with_variable_length_encoding(fi)
		self.ValidityRestrictions = []
		fia = io.BytesIO(validity_restrictions)
		while True:
			vr = {}
			validity_restriction_type = fia.read(1)
			if len(validity_restriction_type) == 0: break

			validity_restriction_type = ValidityRestrictionType(ord(validity_restriction_type))
			vr['type'] = validity_restriction_type
			unique_check = [vri for vri in self.ValidityRestrictions if vri['type'] == validity_restriction_type]
			assert(len(unique_check) == 0)

			if validity_restriction_type == ValidityRestrictionType.time_end:
				vr['end_validity'] = int.from_bytes(fia.read(4), "big")

			elif validity_restriction_type == ValidityRestrictionType.time_start_and_end:
				vr['start_validity'] = int.from_bytes(fia.read(4), "big")
				vr['end_validity'] = int.from_bytes(fia.read(4), "big")

			elif validity_restriction_type == ValidityRestrictionType.region:
				region_type = RegionType.parse(fia)
				vr['region'] = region = {'type': region_type }
				if region_type == RegionType.none:
					pass
				else:
					raise NotImplementedError("validity_restrictions.region_type={}".format(region_type))

			else:
				raise NotImplementedError("validity_restrictions.type={}".format(validity_restriction_type))

			self.ValidityRestrictions.append(vr)

		# Signature
		self.SignaturePosition = fi.tell()
		self.Signature = parse_Signature(fi)

		# We must be at the end of input data
		assert(len(self.Data) == fi.tell())

		self.IsVerified = None
		self.Digest = compute_HashedId8(self)


	def __repr__(self):
		return("[{}/{}]".format(self.Digest.hex(), self.SubjectInfo['subject_type'].name))


	def public_key(self, backend=None):

		# Find a verification key
		sa = next(sa for sa in self.SubjectAttributes if sa['type'] == SubjectAttributeType.verification_key)

		public_key = sa['public_key']
		if public_key['algorithm'] not in (0, 1): return None

		if backend is None:
			backend = cryptography.hazmat.backends.default_backend()

		if public_key['public_key']['type'] == EccPointType.uncompressed:
			# Loading uncompressed EC key

			ecpn = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
				public_key['public_key']['x'],
				public_key['public_key']['y'],
				cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
			)
			return ecpn.public_key(backend)

		else:
			# Loading compressed EC key

			# Assumming that backend is OpenSSL
			curve_nid = backend._elliptic_curve_to_nid(cryptography.hazmat.primitives.asymmetric.ec.SECP256R1())

			ec_cdata = backend._lib.EC_KEY_new_by_curve_name(curve_nid)
			backend.openssl_assert(ec_cdata != backend._ffi.NULL)
			ec_cdata = backend._ffi.gc(ec_cdata, backend._lib.EC_KEY_free)

			group = backend._lib.EC_KEY_get0_group(ec_cdata)
			backend.openssl_assert(group != backend._ffi.NULL)

			point = backend._lib.EC_POINT_new(group)
			backend.openssl_assert(point != backend._ffi.NULL)
			point = backend._ffi.gc(point, backend._lib.EC_POINT_free)

			bnx = backend._ffi.gc(backend._int_to_bn(public_key['public_key']['x']), backend._lib.BN_free)

			res = backend._lib.EC_POINT_set_compressed_coordinates_GFp(
				group,
				point,
				bnx,
				1 if (public_key['public_key']['eccpoint_type'] == 3) else 0,
				backend._ffi.NULL
			);
			if res != 1:
				backend._consume_errors()
				raise ValueError("Invalid EC key.")

			res = backend._lib.EC_KEY_set_public_key(ec_cdata, point)
			if res != 1:
				backend._consume_errors()
				raise ValueError("Invalid EC key.")

			evp_pkey = backend._ec_cdata_to_evp_pkey(ec_cdata)

			return cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey(backend, ec_cdata, evp_pkey)


	def identity(self):
		public_key_bytes = self.public_key().public_bytes(
			cryptography.hazmat.primitives.serialization.Encoding.DER, 
			cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
		)

		# ITS identity is made from a public key (DER SubjectPublicKeyInfo) sha384 hash
		m = hashlib.sha384()
		m.update(public_key_bytes)
		return m.hexdigest()


def parse_SignerInfo(fi):
	signer_info_type = SignerInfoType.parse(fi)
	SignerInfo = {
		'type': signer_info_type,
	}
	if signer_info_type == SignerInfoType.self_signed:
		pass
	elif signer_info_type == SignerInfoType.certificate_digest_with_sha256:
		SignerInfo['digest'] = fi.read(8)
	else:
		raise NotImplementedError("signer_info.type={}".format(signer_info_type))

	return SignerInfo


def parse_Signature(fi):
	signature_algorithm = PublicKeyAlgorithm.parse(fi)
	Signature = {
		'algorithm': signature_algorithm,
	}
	if signature_algorithm == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256:
		Signature['ecdsa_signature'] = parse_EcdsaSignature(fi, signature_algorithm)
	else:
		raise NotImplementedError("signature.algorithm={}".format(signature_algorithm))
	return Signature
