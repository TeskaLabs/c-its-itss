import struct

from .certificate import CITS103097v121Certificate
from .secure_message import CITS103097v121SecureMessage, CITS103097v121SecureMessageBuilder
from .g5sim import G5Simulator


def encode_der_SEQUENCE(value):
	tag = struct.pack(">B", 0x30)
	length = encode_der_length(len(value))
	return tag + length + value


def encode_der_length(seq_len):
	if seq_len < 128:
		# Short form
		msg = struct.pack(">B", seq_len)
	else:
		# Long form
		x = (seq_len).to_bytes(127, 'big').lstrip(b'\x00')
		msg = struct.pack(">B", 0x80 | len(x)) + x

	return msg
