import asyncio
import socket


class G5Simulator(object):

	def __init__(self, loop, config=""):
		confp = config.split(' ')
		if len(confp) == 0:
			confp.append('224.1.1.1') # Default multicast group
		if len(confp) == 1:
			confp.append('5007') # Default multicast port
		if len(confp) == 2:
			confp.append('32') # Multicast TTL
		if len(confp) == 3:
			confp.append('auto') # Multicast interface (IP or 'auto')
		self.mcast_grp, self.mcast_port, self.mcast_ttl, self.mcast_if = confp
		self.mcast_port = int(self.mcast_port)
		self.mcast_ttl = int(self.mcast_ttl)

		if self.mcast_if == 'auto':
			# Find the internet facing IP
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(("8.8.8.8", 80))
			self.mcast_if = s.getsockname()[0]
			s.close()

		self.ReceivingSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.ReceivingSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.ReceivingSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		self.ReceivingSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
		self.ReceivingSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
		self.ReceivingSocket.bind((self.mcast_grp, self.mcast_port))	
		self.ReceivingSocket.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.mcast_if))
		self.ReceivingSocket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(self.mcast_grp) + socket.inet_aton(self.mcast_if))

		self.SendingSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.SendingSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.SendingSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		self.SendingSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

		asyncio.ensure_future(self._run(loop), loop=loop)


	async def _run(self, loop):
		def factory(): return self
		listen = await loop.create_datagram_endpoint(factory, sock=self.ReceivingSocket)


	def connection_made(self, x):
		pass

	def datagram_received(self, data, addr):
		print("Received '{}'' from '{}'".format(data, addr))


	def send(self, msg):
		self.SendingSocket.sendto(msg, (self.mcast_grp, self.mcast_port))

