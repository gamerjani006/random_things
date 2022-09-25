#!/usr/bin/env python3

import http.cookiejar, urllib.parse, urllib.request
from http.cookies import SimpleCookie
from json import loads as json_loads

_headers = {'Referer': 'https://rentry.co'}


class UrllibClient:
	def __init__(self):
		self.cookie_jar = http.cookiejar.CookieJar()
		self.opener = urllib.request.build_opener(
			urllib.request.HTTPCookieProcessor(self.cookie_jar)
		)
		urllib.request.install_opener(self.opener)

	def get(self, url, headers={}):
		request = urllib.request.Request(url, headers=headers)
		return self._request(request)

	def post(self, url, data=None, headers={}):
		postdata = urllib.parse.urlencode(data).encode()
		request = urllib.request.Request(url, postdata, headers)
		return self._request(request)

	def _request(self, request):
		response = self.opener.open(request)
		response.status_code = response.getcode()
		response.data = response.read().decode('utf-8')
		return response


def raw(url):
	client = UrllibClient()
	return json_loads(client.get('https://rentry.co/api/raw/{}'.format(url)).data)


def new(url, edit_code, text):
	client, cookie = UrllibClient(), SimpleCookie()
	cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie'])
	csrftoken = cookie['csrftoken'].value
	payload = {
		'csrfmiddlewaretoken': csrftoken,
		'url': url,
		'edit_code': edit_code,
		'text': text,
	}
	return json_loads(
		client.post('https://rentry.co/api/new', payload, headers=_headers).data
	)


def edit(url, edit_code, text):
	client, cookie = UrllibClient(), SimpleCookie()
	cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie'])
	csrftoken = cookie['csrftoken'].value
	payload = {'csrfmiddlewaretoken': csrftoken, 'edit_code': edit_code, 'text': text}
	return json_loads(
		client.post(
			'https://rentry.co/api/edit/{}'.format(url), payload, headers=_headers
		).data
	)


# Actually starting code lmfao
from ecdsa import SigningKey, VerifyingKey
from passlib.hash import argon2
from Crypto.Cipher import AES
import PySimpleGUI as sg
import hashlib
import base64
import ecdsa
import json
import time


class User:  # TODO add proof of work
	def __init__(self, name):
		self.current_room = None
		self.current_key = None
		self.username = name
		with open('.keypair', 'rb') as file:
			pemkey = file.read()
		if len(pemkey) == 0:
			self.sk = SigningKey.generate()
			self.vk = self.sk.verifying_key
			with open('.keypair', 'wb') as file:
				file.write(self.sk.to_pem())
		else:
			self.sk = SigningKey.from_pem(pemkey)
			self.vk = self.sk.verifying_key

	def update(self, room_link):
		full = raw(room_link)
		self.content = full.get('content')
		self.response = full.get('status')

	def get_info(self, room_link):
		self.update(room_link)
		
		split = self.content.split('\r\n')
		
		self.infoline = split[0]
		self.infoline_parsed = self.infoline.split(';')
		
		self.chat = json.loads(split[1])

		self.current_room = room_link

	def validate_chain(self):
		pass #TODO add chain validation

	def post(self, message, edit_code):
		self.get_info(self.current_room)
		previous_post_hash = hashlib.sha256(json.dumps(self.chat[-1]).encode()).hexdigest()
		
		format_message = {"username": self.username, "prevHash": previous_post_hash, "nonce": None, "pubkey": self.vk.to_string().hex(), "message": encrypt(message.encode(), edit_code.encode()), "signature": self.sk.sign(message.encode()).hex()}
		proof = mine(format_message, 18)
		print(proof)
		self.chat.append(format_message)
		
		new_content = f"{self.infoline}\r\n{json.dumps(self.chat)}"
		
		x = edit(self.current_room, edit_code, new_content)
		return x

def hex_to_bin(digest):
	temp = bin(int('1'+digest, 16))[3:]
	return temp

def mine(data: dict, difficulty):
	nonce=0
	while True:
		data['nonce']=nonce
		hashed = hashlib.sha256(json.dumps(data).encode()).hexdigest()
		to_binary = hex_to_bin(hashed)
		if to_binary.startswith('0'*difficulty):
			return nonce
		nonce += 1

def kdf(key: bytes) -> bytes:
	final = argon2.using(rounds=4, salt=b'00000000').hash(key).split('$')[-1][0:16]
	return final


def encrypt(data: bytes, key: bytes) -> bytes:
	key = kdf(key).encode()
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(data)
	return f"{base64.b64encode(ciphertext).decode()}|{base64.b64encode(nonce).decode()}"

def decrypt(encdata: str, key: bytes) -> bytes:
	encdata = encdata.split('|')
	ciphertext = base64.b64decode(encdata[0])
	nonce = base64.b64decode(encdata[1])
	key = kdf(key).encode()
	
	cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext


def parse_msg(message: dict):
	encryption_key = user.current_key
	pubkey = VerifyingKey.from_string(bytes(bytearray.fromhex(message.get("pubkey"))))
	signature = bytes(bytearray.fromhex(message.get("signature")))
	msg = decrypt(message.get("message"), encryption_key.encode()).decode()
	try:
		verified = pubkey.verify(signature, msg.encode())
		proven = hex_to_bin(hashlib.sha256(json.dumps(message).encode()).hexdigest()).startswith('0'*18)
		if proven:
			return f'[{hashlib.sha3_512(pubkey.to_string()).hexdigest()[0:6]}]{message.get("username")}: {msg}'
		else:
			return f'<INVALID PROOF>'
	except ecdsa.keys.BadSignatureError:
		return f'<UNVERIFIED MESSAGE>'



sg.theme('DarkAmber')

login_layout = [
	[sg.Text('Input your nickname'), sg.In(size=(30, 5), key='-NICK-')],
	[sg.Text('Input room code'), sg.Combo(raw('forumlist')['content'].split('\n'), key='-ROOM-', readonly=True)],
	#[sg.Text('Input room code'), sg.In(size=(30, 5), key='-ROOM-')],
	[sg.Button('Join', key='-JOIN-')],
]

chat_layout = [
	[sg.Multiline('', disabled=True, size=(50, 20), key='-CHATBOX-')],
	[
		sg.Text('Message:'),
		sg.In(key='-MINP-', size=(35), do_not_clear=False),
		sg.Button('Send', key='-MSEND-'),
	],
]

login = True
window = sg.Window('Join room', login_layout)

while True:
	event, values = window.read()

	if event == sg.WIN_CLOSED:
		break

	if not login:
		user.update(user.current_room)
		current = '\n'.join([parse_msg(i) for i in user.chat if parse_msg(i) != None])
		window['-CHATBOX-'].Update(current)

	if event == '-MSEND-':
		if len(values['-MINP-']) != 0:
			_message = values['-MINP-']
			user.update(user.current_room)
			x = user.post(_message, user.current_key)
			if x.get('status') == '200':
				current = '\n'.join([parse_msg(i) for i in user.chat if parse_msg(i) != None])
				window['-CHATBOX-'].Update(current)
			else:
				sg.popup_ok(x.get('content'))

	if event == '-JOIN-':
		if (
			len(values['-ROOM-']) > 1
			and len(values['-NICK-']) < 10
			and len(values['-NICK-']) > 2
		):
			user = User(values['-NICK-'])
			user.get_info(values['-ROOM-'])
			if user.infoline.startswith('chatroom'):
				guess = False
				key_hash = user.infoline_parsed[1]
				while not guess:
					_inp = sg.popup_get_text('Enter Edit Code')
					guess = argon2.verify(_inp, key_hash)
				login = False
				user.current_key = _inp
				window.close()
				window = sg.Window('Chat', chat_layout, finalize=True)
				current = '\n'.join([parse_msg(i) for i in user.chat if parse_msg(i) != None])
				window['-CHATBOX-'].Update(current)
		else:
			sg.Popup('Something went wrong!')
