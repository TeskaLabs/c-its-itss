import enum


class _CITSv121Type(enum.IntEnum):
	
	def __repr__(self):
		return "{}({})".format(self.name, self.value)

	@classmethod
	def parse(cls, inp):
		if isinstance(inp, str):
			return cls[inp]
		elif isinstance(inp, int):
			return cls(inp)
		else:
			x = ord(inp.read(1))
			return cls(x)


class SignerInfoType(_CITSv121Type):
	self_signed = 0 # originally 'self'
	certificate_digest_with_sha256 = 1
	certificate = 2
	certificate_chain = 3
	certificate_digest_with_other_algorithm = 4


class SubjectType(_CITSv121Type):
	enrollment_credential = 0
	authorization_ticket = 1
	authorization_authority = 2
	enrollment_authority = 3
	root_ca = 4
	crl_signer = 5


class SubjectAttributeType(_CITSv121Type):
	verification_key = 0
	encryption_key = 1
	assurance_level = 2
	reconstruction_value = 3
	its_aid_list = 32
	its_aid_ssp_list = 33


class PublicKeyAlgorithm(_CITSv121Type):
	ecdsa_nistp256_with_sha256 = 0
	ecies_nistp256 = 1

	def field_size(self):
		return {
			PublicKeyAlgorithm.ecdsa_nistp256_with_sha256: 32,
			PublicKeyAlgorithm.ecies_nistp256: 32,
		}[self.value]


class EccPointType(_CITSv121Type):
	x_coordinate_only = 0
	compressed_lsb_y_0 = 2
	compressed_lsb_y_1 = 3
	uncompressed = 4


class SymmetricAlgorithm(_CITSv121Type):
	aes_128_ccm = 0


class ValidityRestrictionType(_CITSv121Type):
	time_end = 0
	time_start_and_end = 1
	time_start_and_duration = 2
	region = 3


class RegionType(_CITSv121Type):
	none = 0
	circle = 1
	rectangle = 2
	polygon = 3
	id_region = 4 # originally 'id'


class HeaderFieldType(_CITSv121Type):
	generation_time = 0
	generation_time_standard_deviation = 1
	expiration = 2
	generation_location = 3
	request_unrecognized_certificate = 4
	its_aid = 5
	signer_info = 128
	encryption_parameters = 129
	recipient_info = 130


class PayloadType(_CITSv121Type):
	unsecured = 0
	signed = 1
	encrypted = 2
	signed_external = 3
	signed_and_encrypted = 4


class TrailerFieldType(_CITSv121Type):
	signature = 1
