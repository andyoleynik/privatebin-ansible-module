#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['stableinterface'],
					'supported_by': 'community',
					'metadata_version': '1.0'}

DOCUMENTATION = '''
---
module: paste_bin
short_description: Paste or delete messages in private bin
description:
	- Allows creating a paste in private bin
	- Allows deleting a paste from private bin
version_added: "2.4"
options:
  url:
	description:
	  - The URL of the bin.
	required: False
  action:
	description:
	  - Wether to create a paste or delete an exisitng post.
	default: 'create_paste'
	required: False
  text:
	description:
	  - The plain text to create the paste
  compression:
	description:
	  - Compression of the plain text
	required: False
	default: "zlib"
  burn:
	description:
	  - Wether to burn the paste after read.
	required: False
	default: False
  delete_token:
	description:
	  - Delete token required to delete the paste
	required: False
  password:
	description:
	  - Password to open the paste
	required: False
  discussion:
	description:
	  - If the paste is a discussion or not
	required: False
	default: False
  expiry:
	description:
	  - Expiry of the paste
	required: False
	default: "1day"

author: "Vaibhav Gade (@vaibhav-random)"
requirements:
	- pycryptodome
	- sjcl
	- base58
	- requests
'''

EXAMPLES = '''
# Create Policy ex nihilo
- name: Create a paste
  paste_bin:
	url: "" #URL of paste bin <ex: https://bin.grofer.io/>
	text: "" #req if action is create
	action: <create/delete>
	delete_token: "" #req if action is delete
	password: "" #bae64 encoded / optional


'''

from ansible.module_utils.basic import AnsibleModule
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import json
import requests


CIPHER_ITERATION_COUNT = 100000
CIPHER_SALT_BYTES = 8
CIPHER_BLOCK_BITS = 256
CIPHER_BLOCK_BYTES = int(CIPHER_BLOCK_BITS/8)
CIPHER_TAG_BITS = int(CIPHER_BLOCK_BITS/2)
CIPHER_TAG_BYTES = int(CIPHER_TAG_BITS/8)

class Paste:
	def __init__(self, debug=False):
		self._version = 1
		self._compression = 'zlib'
		self._data = ''
		self._text = ''
		self._key = get_random_bytes(CIPHER_BLOCK_BYTES)
		self._password = ''
		self._debug = debug


	def setPassword(self, password):
		self._password = password


	def setText(self, text):
		self._text = text


	def setCompression(self, comp):
		self._compression = comp


	def getText(self):
		return self._text


	def json_encode(self,s):
		return json.dumps(s, separators=(',',':')).encode()


	def getJSON(self):
		return self._data


	def getHash(self):
		return b64encode(self._key).decode()


	def setHash(self, hash):
		if self._version == 2:
			from base58 import b58decode
			self._key = b58decode(hash)
		else:
			self._key = b64decode(hash)


	def __compress(self, s):
		import zlib
		# co = zlib.compressobj()
		# b = co.compress(s) + co.flush()
		# return b64encode(''.join(map(chr, b)).encode('utf-8'))
		return b64encode(zlib.compress(s.encode('utf-8')))


	def encrypt(self, formatter, burnafterreading, discussion, expiration):

		from hashlib import sha256
		from sjcl import SJCL

		self._data = {'expire':expiration,'formatter':formatter,'burnafterreading':int(burnafterreading),'opendiscussion':int(discussion)}

		if self._password:
			digest = sha256(self._password.encode("UTF-8")).hexdigest()
			password = b64encode(self._key) + digest.encode("UTF-8")
		else:
			password = b64encode(self._key)

		# Encrypting text
		cipher = SJCL().encrypt(self.__compress(self._text.encode('utf-8')), password, mode='gcm')
		for k in ['salt', 'iv', 'ct']: cipher[k] = cipher[k].decode()

		self._data['data'] = self.json_encode(cipher)


def post(server, request):
	headers = {'X-Requested-With': 'JSONHttpRequest'}
	result = requests.post(
		url = server,
		headers = headers,
		data = request)
	try:
		return result.json()
	except ValueError as e:
		val_error = "ERROR: Unable parse response as json. Received (size = {}):\n".format(len(result.text), result.text)
		return True, False, val_error

def create_paste(data):
	has_changed = False
	#Validate data entered
	if not data['text']:
		return (False, False, "Text has to be entered for creating a paste")

	paste = Paste(debug=True)

	paste.setText(data['text'])

	if data['password']:
		paste.setPassword(data['password'])

	paste.encrypt(
		formatter = "plaintext",
		burnafterreading = data['burn'],
		discussion = data['discussion'],
		expiration = data['expiry'])

	request = paste.getJSON()

	result = post(data['url'],request)

	if 'status' in result and not result['status']:
		passphrase = paste.getHash()
		paste_link = data['url']+"?"+result['id']+"#"+passphrase
		meta = {
		"Paste_id":result['id'],
		"Passphrase":passphrase,
		"Delete_token":result['deletetoken'],
		"Link":paste_link
		}

		return False, True, meta

	elif 'status' in result and result['status']:
		return True, False, "Something went wrong...\nError:\t\t{}".format(result['message'])
	else:
		return True, False, "Something went wrong...\nError: Empty response."

def delete_paste(data):
	has_changed = False
	#Validate data entered
	if not data['delete_token']:
		return True, False, "Delete token has to be entered for deleting the paste"
	pass

def main():

	fields = {
		"url":
			{
				"required": False,
				"default": "https://bin.grofer.io/",
				"type": "str"
			},
		"action":
			{
				"default": "create_paste",
				"choices": ['create_paste', 'create_paste'],
				"type": 'str'
			},
		"text" :
		{
			"required": False,
			"type": "str"
		},
		"compression":
		{
			"required": False,
			"default": "zlib",
			"type": "str"
		},
		"burn":
			{
				"required": False,
				"default": False,
				"type": "bool"
			},
		"delete_token":
			{
				"required": False,
				"type": "str"
			},
		"password":
			{
				"required": False,
				"type": "str"
			},
		"discussion":
			{
				"required": False,
				"default": False,
				"type": "bool"
			},
		"expiry":
			{
				"required": False,
				"choices" : ["5min", "10min", "1hour", "1day", "1week", "1month", "1year", "never"],
				"default": "1hour",
				"type": 'str'
			}
	}

	choice_map = {
	  "create_paste": create_paste,
	  "delete_paste": delete_paste,
	}

	module = AnsibleModule(argument_spec=fields)

	is_error, has_changed, result = choice_map.get(module.params['action'])(module.params)

	if is_error:
		module.fail_json(msg="Error while performing action", meta=result)
	else:
		module.exit_json(changed=has_changed, meta=result)



if __name__ == '__main__':
	main()
