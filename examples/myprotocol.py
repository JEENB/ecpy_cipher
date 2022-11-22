from inspect import trace
from ecpy import ExtendedFiniteField, EllipticCurve, MapToPoint
from ecpy import symmetric_tate_pairing
import hashlib




class DomainParameter:

	def __init__(self) -> None:
		self.p = int("519130854181216822940010183929228824799903608965854344652247095061840"
					"171046331806216450362399027718738907160814923275136184823731671523533"
					"69121135029626237")
		self.l = int((self.p + 1) / 6) ##not sure if int can be
		self.F = ExtendedFiniteField(self.p, "x^2+x+1")
		self.E = EllipticCurve(self.F, 0, 1)

		self.P = self.E(6, (int("132232566129358054566854866197859888282113525457609791458267738"
								"093383172947853439119386209153000327873055642240731797496321750"
								"04531990130007962275678599731"),
							int("264465132258716109133709732395719776564227050915219582916535476"
								"186766345895706878238772418306000655746111284481463594992643500"
								"09063980260015924551357199462")))

class Server(DomainParameter):
	def __init__(self) -> None:
		DomainParameter.__init__(self)
		self.key_record = dict()
		self.trace_pool = list()

	def trace(self, message:dict):
		print("starting trace")
		# msg_mtd = self.trace_pool[0]
		msg = message["message"]
		pk = message["public_key"]
		field_point = message["field_point"]
		sign = message["signature"]

		h = int(hashlib.sha512(msg.encode("utf-8")).hexdigest(), 16)
		ephermal_pairing = symmetric_tate_pairing(self.E, pk, MapToPoint(self.E, self.E.field(h)), self.l)
		# for master_public_keys in self.key_record.values():
		commitment_pairing = symmetric_tate_pairing(self.E, 0xceadbeee*self.P, MapToPoint(self.E, self.E.field(h)), self.l)
		### check if commitment pairing * ephermal pairing = field point
		res = self.F._div(field_point, ephermal_pairing)
		if res == commitment_pairing:
			print("yes")
		else:
			print("no")

class Client(Server):
	def __init__(self, client_name:str) -> None:
		# DomainParameter.__init__(self)
		Server.__init__(self)
		self.client_name = client_name
		self.msg_db = dict()

	def generate_master_key(self):
		self.master_secret = 0xceadbeee
		self.master_public = self.master_secret * self.P
		self.key_record[self.client_name] = self.master_public


	def generate_signing_key(self):
		self.secret =  0xdeadbeef
		self.public = self.secret * self.P
		return self.secret, self.public

	def sign_and_send(self, message:str):
		print("Message Sent")
		m = {}
		h = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16)
		sk, pk = self.generate_signing_key()
		m["signature"] = sk * MapToPoint(self.E, self.E.field(h))
		m["field_point"] = symmetric_tate_pairing(self.E, pk, m["signature"], self.l)
		m["message"] = message
		m["public_key"] = pk
		return m

	def receive_msg(self, msg: dict):
		print("Message Recieved")
		i = len(self.msg_db)
		self.msg_db[i+1] = msg

	def report_msg(self, id):
		print("Trace Message Received")
		self.trace_pool.append(self.msg_db[id])
		print(self.trace_pool)
		

d = DomainParameter()
s = Server()

Alice = Client("Alice")
Alice.generate_master_key()
alice_msg = Alice.sign_and_send("hi")



Bob = Client("Bob")
Bob.generate_master_key()
Bob.receive_msg(alice_msg)
Bob.report_msg(1)   ## reporting alice's message

s.trace(alice_msg)