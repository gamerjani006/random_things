import hashlib, secrets, uuid
from dataclasses import dataclass, astuple, asdict

'''
database entry:
"uuid": {"username": "james", "password": "mypassword123"}
'''

class Database:
	def __init__(self):
		self.db={}

@dataclass
class User:
	username: str
	password: str
	salt: bytes = secrets.token_urlsafe(16)[0:16].encode()
	uuid: str = str(uuid.uuid4())

	def __post_init__(self):
		self.password = hashlib.blake2b(self.password.encode(), salt=self.salt, digest_size=24).hexdigest()

	def __repr__(self):
		kws = [f"{key}={value!r}" for key, value in self.__dict__.items()]
		return "{}({})".format(type(self).__name__, ", ".join(kws))

x = User('username', 'password')
print(asdict(x))

