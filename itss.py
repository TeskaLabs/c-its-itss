#!/usr/bin/env python3.7
import pprint
import struct
import datetime
import argparse
import sys
import os
import asyncio
import traceback
import platform
import uuid

import requests

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.serialization

import asn1tools

import itss


class ITSS(object):


	fname = './ts_102941_v111.asn'
	asn1 = asn1tools.compile_files(fname, 'der')

	def __init__(self, tenant, directory, ea_url, aa_url, hsm):
		self.EC = None # Enrollment credentials
		self.AT = None # Authorization ticket

		if not os.path.isdir(directory):
			os.mkdir(directory)
		self.Directory = directory

		self.AA_url = aa_url + '/' + tenant
		self.EA_url = ea_url + '/' + tenant

		self.Certs = {}

		cert_dir = os.path.join(self.Directory, "certs")
		if not os.path.isdir(cert_dir):
			os.mkdir(cert_dir)

		if hsm == 'emulated':
			import itss.hsm_emulated
			self.HSM = itss.hsm_emulated.EmulatedHSM(self.Directory)
		elif hsm == 'cicada':
			import itss.hsm_cicada
			self.HSM = itss.hsm_cicada.CicadaHSM()
		else:
			raise RuntimeError("Unknown/unsupported HSM '{}'".format(hsm))


	def generate_private_key(self):
		self.HSM.generate_private_key()
		self.EC = None
		self.AT = None


	def enroll(self, enrollment_id):
		'''
		Send Enrollment request to Enrollment Authority and process the response.
		The process is described in CITS / ETSI TS 102 941 V1.1.1
		'''

		verification_public_key = self.HSM.get_public_key()
		verification_public_numbers = verification_public_key.public_numbers()

		response_encryption_private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
			cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
			cryptography.hazmat.backends.default_backend()
		)

		response_encryption_public_key = response_encryption_private_key.public_key()
		response_encryption_public_numbers = response_encryption_public_key.public_numbers()

		requestTime = int((datetime.datetime.utcnow() - datetime.datetime(2004,1,1)).total_seconds())
		expiration = requestTime +  3600 # 1 hour

		EnrolmentRequest = \
		{
			# The canonical certificate or the public/private key pair that uniquely identifies the ITS-S
			'signerEnrolRequest': 
			{
				'type': 3, # SignerIdType.certificate (fixed)
				'digest': b'12345678',
				'id': enrollment_id.encode('utf-8'), # Can be used to link request with a preauthorization at EA
			},
			'enrolCertRequest':
			{
				'versionAndType': 2, # explicitCert (fixed)
				'requestTime': requestTime,
				'subjectType': 3, # SecDataExchCsr (fixed)
				'cf': (b'\0',0), # useStartValidity, shall not be set to include the encryption_key flag
				'enrolCertSpecificData': {
					'eaId': 'EAName', # Name (What to set?)
					'permittedSubjectTypes': 0, # secDataExchAnonymousSubj (or secDataExchidentifiedLocalizedSubj)
					'permissions': { # PsidSspArray
						'type': 1, # ArrayType / specified
						'permissions-list': [] # shall contain a list of the ETSI ITS-AIDs to be supported.
					},
					'region': {
						'region-type': 0 # RegionType / from-issuer
					}
				},
				'expiration': requestTime,
				'verificationKey': {
					'algorithm': 1, # PKAlgorithm ecdsaNistp256WithSha256 (fixed)
					'public-key': {
						'type': 'uncompressed', # EccPublicKeyType uncompressed
						'x': (
							'ecdsa-nistp256-with-sha256-X',
							verification_public_numbers.x
						),
						'y': (
							'ecdsa-nistp256-with-sha256-Y',
							verification_public_numbers.y
						)
					}
				},
				'responseEncryptionKey': {
					'algorithm': 1, # PKAlgorithm ecdsaNistp256WithSha256
					'public-key': {
						'type': 'compressedLsbY0', # EccPublicKeyType compressedLsbY0
						'x': (
							'ecdsa-nistp256-with-sha256-X',
							response_encryption_public_numbers.x,
						)
					}
				},
			}
		}

		encoded_er = b''
		encoded_er += struct.pack(">B", 0xa0) + self.asn1.encode('SignerIdentifier', EnrolmentRequest['signerEnrolRequest'])[1:]
		encoded_er += struct.pack(">B", 0xa1) + self.asn1.encode('ToBeSignedEnrolmentCertificateRequest', EnrolmentRequest['enrolCertRequest'])[1:]

		# Sign with ecdsa_nistp256_with_sha256
		r, s = self.HSM.sign(encoded_er)

		EnrolmentRequest['signature'] = {
			'r': {
				'type': 'xCoordinateOnly',
				'x': ('ecdsa-nistp256-with-sha256-X', r),
			},
			's': ('ecdsa-nistp256-with-sha256-s', s)
		}
		encoded_er += struct.pack(">B", 0xa2) + self.asn1.encode('Signature', EnrolmentRequest['signature'])[1:]

		encoded_er = itss.encode_der_SEQUENCE(encoded_er)
	
		# Send request to Enrollment Authority
		r = requests.put(self.EA_url + '/cits/ts_102941_v111/ea/enroll', data=encoded_er)
		
		EnrolmentResponse = self.asn1.decode('EnrolmentResponse', r.content)
		if EnrolmentResponse[0] != 'successfulEnrolment':
			print("Enrollment failed!")
			pprint.pprint(EnrolmentResponse)
			sys.exit(1)

		print("Enrollment finished successfuly.")
		self.EC = itss.CITS103097v121Certificate(EnrolmentResponse[1]['signedCertChain']['rootCertificate'])


	def authorize(self):
		requestTime = int((datetime.datetime.utcnow() - datetime.datetime(2004,1,1)).total_seconds())
		expiration = requestTime +  3600 # 1 hour

		AuthorizationRequest = {

			# The enrolment certificate containing the pseudonymous identifier to be used by the ITS-S
			'signerAuthRequest': {
				'type': 3, # SignerIdType.certificate (fixed)
				'digest': self.EC.Digest,
				'id': uuid.uuid4().hex.encode('ascii'), #TODO: Check if this is pseudorandom ID
			},

			'authCertRequest' : ('anonRequest', {
				'versionAndType': 2, # explicitCert (fixed)
				'requestTime': requestTime,
				'subjectType': 0, # SecDataExchAnon (fixed)
				'cf': (b'\0',0), # useStartValidity
				'authCertSpecificData': {
					'additional-data': b'ahoj',
					'permissions': { # PsidSspArray
						'type': 1, # ArrayType / specified
						'permissions-list': [] # shall contain a list of the ETSI ITS-AIDs to be supported.
					},
					'region': {
						'region-type': 0 # RegionType / from-issuer
					}
				},
				'responseEncryptionKey': {
					'algorithm': 1, # PKAlgorithm ecdsaNistp256WithSha256
					'public-key': {
						'type': 'compressedLsbY0', # EccPublicKeyType compressedLsbY0
						'x': (
							'ecdsa-nistp256-with-sha256-X',
							0, #response_encryption_public_numbers.x,
						)
					}
				},
			}),
		}

		encoded_ar = b''
		encoded_ar += struct.pack(">B", 0xa0) + self.asn1.encode('SignerIdentifier', AuthorizationRequest['signerAuthRequest'])[1:]
		acr = struct.pack(">B", 0xa0) + self.asn1.encode('AuthCertRequest', AuthorizationRequest['authCertRequest'])[1:]
		encoded_ar += struct.pack(">B", 0xa1) + itss.encode_der_length(len(acr)) + acr

		# Sign with ecdsa_nistp256_with_sha256
		r, s = self.HSM.sign(encoded_ar)

		AuthorizationRequest['signature'] = {
			'r': {
				'type': 'xCoordinateOnly',
				'x': ('ecdsa-nistp256-with-sha256-X', r),
			},
			's': ('ecdsa-nistp256-with-sha256-s', s)
		}

		encoded_ar += struct.pack(">B", 0xa2) + self.asn1.encode('Signature', AuthorizationRequest['signature'])[1:]
		encoded_ar = itss.encode_der_SEQUENCE(encoded_ar)

		# Send request to Authorization Authority
		r = requests.put(self.AA_url + '/cits/ts_102941_v111/aa/approve', data=encoded_ar)

		AuthorizationResponse = self.asn1.decode('AuthorizationResponse', r.content)
		if AuthorizationResponse[0] not in ('successfulExplicitAuthorization', 'successfulImplicitAuthorization'):
			print("Authorization failed!")
			pprint.pprint(AuthorizationResponse)
			sys.exit(1)

		# TODO: Handle also CRL (they can be part of the AuthorizationResponse)

		print("Authorization ticket obtained successfuly.")
		self.AT = itss.CITS103097v121Certificate(AuthorizationResponse[1]['signedCertChain']['rootCertificate'])



	def store(self):
		self.HSM.store()

		if self.EC is not None:
			open(os.path.join(self.Directory, 'itss.ec'),'wb').write(self.EC.Data)
		else:
			os.unlink(os.path.join(self.Directory, 'itss.ec'))

		if self.AT is not None:
			open(os.path.join(self.Directory,'itss.at'), 'wb').write(self.AT.Data)
		else:
			os.unlink(os.path.join(self.Directory, 'itss.at'))


	def load(self):
		assert(self.EC is None)
		assert(self.AT is None)

		ok = self.HSM.load()
		if not ok:
			return False

		try:
			ecraw = open(os.path.join(self.Directory, 'itss.ec'),'rb').read()
		except FileNotFoundError:
			pass
		else:
			self.EC = itss.CITS103097v121Certificate(ecraw)

		try:
			atraw = open(os.path.join(self.Directory, 'itss.at'),'rb').read()
		except FileNotFoundError:
			pass
		else:
			self.AT = itss.CITS103097v121Certificate(atraw)

		return True


	def get_certificate_by_digest(self, digest):
		'''
		Obtain certificate by its digest.
		Firstly, look at the certificate store in a memory.
		Secondly, look at the certificate store at the local drive.
		Lastly, use AA API to fetch certficate.
		'''
		try:
			return self.Certs[digest]
		except KeyError:
			pass

		cert_fname = os.path.join(self.Directory, "certs", digest.hex() + '.cert')

		cert = None
		try:
			f = open(cert_fname, 'rb')
			data = f.read()
			cert = itss.CITS103097v121Certificate(data)

		except FileNotFoundError:
			cert = None

		if cert is None:
			r = requests.get(self.AA_url + '/cits/digest/{}'.format(digest.hex()))
			cert = itss.CITS103097v121Certificate(r.content)
			self.store_certificate(cert)

		self.Certs[digest] = cert
		return cert


	def store_certificate(self, certificate):
		cert_fname = os.path.join(self.Directory, "certs", certificate.Digest.hex() + '.cert')
		open(cert_fname, 'wb').write(certificate.Data)


def main():
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=\
'''C-ITS ITS-S reference implementation focused on a security.
C-ITS standards: ETSI TS 102 941 v1.1.1, ETSI TS 103 097 v1.2.1
This tool also provides a simple ITS-G5 network simulator that utilizes UDP IPv4 multicast.

Copyright (c) 2018 TeskaLabs Ltd, MIT Licence
''')

	parser.add_argument('DIR', default='.', help='A directory with persistent storage of a keying material')
	parser.add_argument('-e', '--ea-url', default="https://via.teskalabs.com/croads/demo-ca", help='URL of the Enrollment Authority')
	parser.add_argument('-a', '--aa-url', default="https://via.teskalabs.com/croads/demo-ca", help='URL of the Authorization Authority')
	parser.add_argument('-i', '--enrollment-id', help='Specify a custom enrollment ID')
	parser.add_argument('-H', '--hsm', default="emulated", choices=['cicada', 'emulated'], help='Use the HSM to store a private key.')
	parser.add_argument('--g5-sim', default="224.1.1.1 5007 32 auto", help='Configuration of G5 simulator')
	parser.add_argument('-t', '--tenant', default="c-its", help='Client tenant')

	args = parser.parse_args()

	itss_obj = ITSS(args.tenant, args.DIR, args.ea_url, args.aa_url, args.hsm)
	ok = itss_obj.load()
	store = False
	if not ok:
		itss_obj.generate_private_key()
		store = True

	if itss_obj.EC is None:
		# Enrollment Id is an pre-approved identification of the ITS-S from the manufacturer (e.g. Serial Number)
		# It should also contain an information about the vendor
		enrollment_id = args.enrollment_id
		if enrollment_id is None:
				enrollment_id = 'itss.py/{}/{}'.format(platform.node(), uuid.uuid4())
		itss_obj.enroll(enrollment_id)
		store = True

	if itss_obj.AT is None:
		itss_obj.authorize()
		store = True

	if store:
		itss_obj.store()

	print("ITS-S identity: {}".format(itss_obj.EC.identity()))
	print("AT digest: {}".format(itss_obj.AT.Digest.hex()))


	loop = asyncio.get_event_loop()


	# Create simulator and a handling routine for inbound messages
	class MyG5Simulator(itss.G5Simulator):
		def datagram_received(self, data, addr):
			try:
				msg = itss.CITS103097v121SecureMessage(data)
				signer_certificate = msg.verify(itss_obj)
				print("Received verified message {} from {}".format(msg.Payload, signer_certificate))
			except Exception as e:
				print("Error when processing message")
				traceback.print_exc()

	g5sim = MyG5Simulator(loop, args.g5_sim)
	# Send out some payload periodically
	async def periodic_sender():
		while True:
			smb = itss.CITS103097v121SecureMessageBuilder()
			msg = smb.finish(itss_obj.AT, itss_obj.HSM, "payload from '{}'".format(platform.node()))

			g5sim.send(msg)
			await asyncio.sleep(1)
	
	asyncio.ensure_future(periodic_sender(), loop=loop)


	print("Ready.")

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()


if __name__ == '__main__':
	main()

