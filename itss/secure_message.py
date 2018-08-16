import struct
import io

from .ts_103097_utils import *
from .enums import *
from .certificate import parse_SignerInfo, parse_Signature


class CITS103097v121SecureMessage(object):
	'''
	ETSI TS 103 097 V1.2.1
	'''

	Version = 2

	def __init__(self, data:bytes):
		self.Data = data
		fi = io.BytesIO(data)

		self.ProtocolVersion = ord(fi.read(1))
		assert(self.ProtocolVersion == self.Version)

		# Headers
		self.Headers = {}
		header_fields = parse_var_length_vectors_with_variable_length_encoding(fi)
		fia = io.BytesIO(header_fields)
		while True:
			header_field_type = fia.read(1)
			if len(header_field_type) == 0: break
			header_field_type = HeaderFieldType(ord(header_field_type))

			if header_field_type == HeaderFieldType.signer_info:
				self.Headers['SignerInfo'] = parse_SignerInfo(fia)

			elif header_field_type == HeaderFieldType.generation_time:
				#TODO: Parse time correctly
				self.Headers['GenerationTime'] = fia.read(8)

			else:
				raise NotImplementedError("header_field.type={}".format(header_field_type))

		# Payload
		self.PayloadType = PayloadType.parse(fi)
		if self.PayloadType == PayloadType.signed_external:
			self.Payload = None
		else:
			self.Payload = parse_var_length_vectors_with_variable_length_encoding(fi)

		# Trailer
		trailer_position = fi.tell()
		trailer_fields = parse_var_length_vectors_with_variable_length_encoding(fi)
		fia = io.BytesIO(trailer_fields)
		while True:
			trailer_field_type = fia.read(1)
			if len(trailer_field_type) == 0: break
			trailer_field_type = TrailerFieldType(ord(trailer_field_type))

			if trailer_field_type == TrailerFieldType.signature:
				self.SignaturePosition = fia.tell() + trailer_position
				self.Signature = parse_Signature(fia)
			else:
				raise NotImplementedError("trailer_field.type={}".format(trailer_field_type))

		# We must be at the end of input data
		assert(len(self.Data) == fi.tell())

		self.IsVerified = None


	def verify(self, itss):
		'''
		This method verifies the message signature.
		Raises the exception if failed
		'''

		signer_certificate = None
		if self.Headers['SignerInfo']['type'] == SignerInfoType.certificate_digest_with_sha256:
			signer_digest = self.Headers['SignerInfo']['digest']
			signer_certificate = itss.get_certificate_by_digest(signer_digest)
		else:
			raise RuntimeError("Unsupported SignerInfo type {}".format(self.Headers['SignerInfo']['type']))

		s = int.from_bytes(self.Signature['ecdsa_signature']['s'], byteorder='big')
		r = self.Signature['ecdsa_signature']['R']['x']

		signer_pubkey = signer_certificate.public_key()
		signer_pubkey.verify(
			cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(r, s),
			self.Data[:self.SignaturePosition],
			cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
				cryptography.hazmat.primitives.hashes.SHA256()
			)
		)

		if signer_certificate is None:
			raise RuntimeError("Unable to find the authorization ticket for a received message.")

		return signer_certificate


class CITS103097v121SecureMessageBuilder(object):

	Version = 2

	def _build_HeaderField(self, autorization_ticket):
		hf = b''

		# Signer info
		hf += struct.pack(">BB", HeaderFieldType.signer_info, SignerInfoType.certificate_digest_with_sha256)
		hf += autorization_ticket.Digest

		# Generation time
		#TODO: Use proper time
		hf += struct.pack(">BQ", HeaderFieldType.generation_time, 0x0802030405060701)

		return build_var_length_vectors_with_variable_length_encoding(hf)


	def _build_Trailer(self, r, s):
		tf = b''

		# Signature
		tf += struct.pack(">B", TrailerFieldType.signature)
		covered_by_signature = len(tf)

		tf += struct.pack(">B", PublicKeyAlgorithm.ecdsa_nistp256_with_sha256)
		tf += build_EccPoint_x_coordinate_only(r)
		tf += s.to_bytes(32, 'big') # Signature EcdsaSignature s

		return covered_by_signature, build_var_length_vectors_with_variable_length_encoding(tf)


	def finish(self, autorization_ticket, hsm, payload):
		msg = struct.pack(">B", self.Version)
		msg += self._build_HeaderField(autorization_ticket)
		
		# Payload
		msg += struct.pack(">B", PayloadType.signed)
		msg += build_var_length_vectors_with_variable_length_encoding(payload)

		# Trailer, start with a fake one to allow proceed with signature
		covered_by_signature, trailer = self._build_Trailer(0, 0)

		# Trailer with signature / ecdsa_nistp256_with_sha256
		r, s = hsm.sign(msg + trailer[:covered_by_signature])
		_, trailer = self._build_Trailer(r, s)

		return msg + trailer
