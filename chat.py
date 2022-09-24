#!/usr/bin/env python3

import http.cookiejar,urllib.parse,urllib.request
from http.cookies import SimpleCookie
from json import loads as json_loads
_headers={'Referer':'https://rentry.co'}
class UrllibClient:
	def __init__(self):self.cookie_jar=http.cookiejar.CookieJar();self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar));urllib.request.install_opener(self.opener)
	def get(self,url,headers={}):request=urllib.request.Request(url,headers=headers);return self._request(request)
	def post(self,url,data=None,headers={}):postdata=urllib.parse.urlencode(data).encode();request=urllib.request.Request(url,postdata,headers);return self._request(request)
	def _request(self,request):response=self.opener.open(request);response.status_code=response.getcode();response.data=response.read().decode('utf-8');return response
def raw(url):client=UrllibClient();return json_loads(client.get('https://rentry.co/api/raw/{}'.format(url)).data)
def new(url,edit_code,text):client,cookie=UrllibClient(),SimpleCookie();cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie']);csrftoken=cookie['csrftoken'].value;payload={'csrfmiddlewaretoken':csrftoken,'url':url,'edit_code':edit_code,'text':text};return json_loads(client.post('https://rentry.co/api/new',payload,headers=_headers).data)
def edit(url,edit_code,text):client,cookie=UrllibClient(),SimpleCookie();cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie']);csrftoken=cookie['csrftoken'].value;payload={'csrfmiddlewaretoken':csrftoken,'edit_code':edit_code,'text':text};return json_loads(client.post('https://rentry.co/api/edit/{}'.format(url),payload,headers=_headers).data)

# Actually starting code lmfao
#from dataclasses import dataclass, asdict
#from ecdsa import SigningKey
import PySimpleGUI as sg
#import library
import json


class User: #TODO add proof of work
	def __init__(self, name):
		self.current_room = None
		self.username = name
		#self.sk = SigningKey.generate()
		#self.vk = self.sk.verifying_key

	def get_content(self, room_link):
		self.full = raw(room_link)
		self.content = self.full.get('content')
		self.response = self.full.get('status')
		
		try:
			self.infoline, self.chatline = self.content.split('\r\n')
			self.chatline = json.loads(self.chatline)
		except ValueError:
			pass

	def join_room(self, room_link): #TODO add an entry code(edit code), also use edit code as key
		self.get_content(room_link)
		if self.response != '200':
			print('Error', self.response)
			return False
		
		try:
			self.infoline, self.chatline = self.content.split('\r\n')
			self.chatline = json.loads(self.chatline)
			self.current_room = room_link
			return True
		except ValueError:
			sg.Popup('Invalid room code!')
		
	def post(self, message, edit_code):
		self.get_content(self.current_room)
		self.chatline.append(f'{self.username}: {message}')
		new_content = f'{self.infoline}\r\n{json.dumps(self.chatline)}'
		x = edit(self.current_room, edit_code, new_content)
		return x



sg.theme('DarkAmber')

login_layout = [
[sg.Text('Input your nickname'), sg.In(size=(30,5), key='-NICK-')],
[sg.Text('Input room code'), sg.In(size=(30,5), key='-ROOM-')],
[sg.Button('Join', key='-JOIN-')]
]

chat_layout = [
[sg.Multiline('', disabled=False, size=(50,20), key='-CHATBOX-')],
[sg.Text('Passwrd:'), sg.In(key='-EC-', size=(42))],
[sg.Text('Message:'), sg.In(key='-MINP-', size=(35)), sg.Button('Send', key='-MSEND-')],
]

login=True

window = sg.Window('Join room', login_layout)

while True:
	event, values = window.read()
	
	if event == sg.WIN_CLOSED:
		break
	
	if not login:
		user.get_content(user.current_room)
		window['-CHATBOX-'].Update(disabled=False)
		window['-CHATBOX-'].Update('\n'.join(user.chatline))
		window['-CHATBOX-'].Update(disabled=True)
	
	if event == '-MSEND-':
		if len(values['-MINP-']) != 0:
			x = user.post(values['-MINP-'], values['-EC-'])
			if x.get('status') == '200':
				window['-EC-'].Update(disabled=True)
				window['-CHATBOX-'].Update(disabled=False)
				window['-CHATBOX-'].Update('\n'.join(user.chatline))
				window['-CHATBOX-'].Update(disabled=True)
			else:
				sg.Popup(x)

	if event == '-JOIN-':
		if len(values['-ROOM-']) > 1  and values['-NICK-'] != '' and len(values['-NICK-']) < 10 and len(values['-NICK-']) > 3:
			user = User(values['-NICK-'])
			x = user.join_room(values['-ROOM-'])
			if x and user.infoline=='-CHATROOM-':
				login=False
				window.close()
				window = sg.Window('Chat', chat_layout, finalize=True)
				window['-CHATBOX-'].Update('\n'.join(user.chatline))
				window['-CHATBOX-'].Update(disabled=True)
	#print(event, values)