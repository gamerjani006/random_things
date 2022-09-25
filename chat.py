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
# from dataclasses import dataclass, asdict
import ecdsa
from ecdsa import SigningKey, VerifyingKey
import PySimpleGUI as sg
import hashlib
# import library
import json
import time


class User:  # TODO add proof of work
	def __init__(self, name):
		self.current_room = None
		self.current_key = None
		self.username = name
		self.sk = SigningKey.generate()
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

	def post(self, message, edit_code):
		self.update(self.current_room)
		
		format_message = {"username": self.username, "pubkey": self.vk.to_string().hex(), "message": message, "signature": self.sk.sign(message.encode()).hex()}
		self.chat.append(format_message)
		
		new_content = f"{self.infoline}\r\n{json.dumps(self.chat)}"
		
		x = edit(self.current_room, edit_code, new_content)
		return x

def kdf(key: bytes, digest_length: int) -> bytes:
	final = b''
	current_byte = b''
	for i in range(digest_length):
		current_byte = hashlib.sha3_512(current_byte + key + str(i).encode() + str(digest_length).encode()).hexdigest()[i%64].encode()
		final += current_byte
		
	return final


def crypt(data: bytes, key: bytes) -> bytes:
	key = kdf(key, len(data))
	finished = bytes([i ^ key[c] for c,i in enumerate(data)])
	return finished


def parse_msg(message: dict):
	pubkey = VerifyingKey.from_string(bytes(bytearray.fromhex(message.get("pubkey"))))
	signature = bytes(bytearray.fromhex(message.get("signature")))
	msg = message.get("message")
	try:
		verified = pubkey.verify(signature, msg.encode())
		return f'{message.get("username")}: {msg}'
	except ecdsa.keys.BadSignatureError:
		print(f"Message {message}\nIs not verifiable!")
		return None



sg.theme('DarkAmber')

login_layout = [
	[sg.Text('Input your nickname'), sg.In(size=(30, 5), key='-NICK-')],
	[sg.Text('Input room code'), sg.In(size=(30, 5), key='-ROOM-')],
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
		#current = '\n'.join([parse_msg(i) for i in user.chat if parse_msg(i) != None])
		#window['-CHATBOX-'].Update(current)

	if event == '-MSEND-':
		if len(values['-MINP-']) != 0:
			_message = values['-MINP-']
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
				guess = None
				key_hash = user.infoline_parsed[2]
				salt = user.infoline_parsed[1]
				while guess != key_hash:
					_inp = sg.popup_get_text('Enter Edit Code')
					guess = hashlib.blake2s(_inp.encode(), salt=salt.encode()).hexdigest()
				login = False
				user.current_key = _inp
				window.close()
				window = sg.Window('Chat', chat_layout, finalize=True)
				current = '\n'.join([parse_msg(i) for i in user.chat if parse_msg(i) != None])
				window['-CHATBOX-'].Update(current)
		else:
			sg.Popup('Something went wrong!')
