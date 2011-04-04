#!/usr/bin/python
#
# Copyright 2011 Jeff Garzik
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

import time
import json
import pprint
import hashlib
import struct
import re
import base64
import httplib
import sys
from multiprocessing import Process

ERR_SLEEP = 15
MAX_NONCE = 1000000

settings = {}
pp = pprint.PrettyPrinter(indent=4)

class BitcoinRPC:
	OBJID = 1

	def __init__(self, host, port, username, password):
		authpair = "%s:%s" % (username, password)
		self.authhdr = "Basic %s" % (base64.b64encode(authpair))
		self.conn = httplib.HTTPConnection(host, port, False, 30)
	def rpc(self, method, params=None):
		self.OBJID += 1
		obj = { 'version' : '1.1',
			'method' : method,
			'id' : self.OBJID }
		if params is None:
			obj['params'] = []
		else:
			obj['params'] = params
		self.conn.request('POST', '/', json.dumps(obj),
			{ 'Authorization' : self.authhdr,
			  'Content-type' : 'application/json' })

		resp = self.conn.getresponse()
		if resp is None:
			print "JSON-RPC: no response"
			return None

		body = resp.read()
		resp_obj = json.loads(body)
		if resp_obj is None:
			print "JSON-RPC: cannot JSON-decode body"
			return None
		if 'error' in resp_obj and resp_obj['error'] != None:
			return resp_obj['error']
		if 'result' not in resp_obj:
			print "JSON-RPC: no result in object"
			return None

		return resp_obj['result']
	def getblockcount(self):
		return self.rpc('getblockcount')
	def getwork(self, data=None):
		return self.rpc('getwork', data)

def uint32(x):
	return x & 0xffffffffL

def bytereverse(x):
	return uint32(( ((x) << 24) | (((x) << 8) & 0x00ff0000) |
			(((x) >> 8) & 0x0000ff00) | ((x) >> 24) ))

def bufreverse(in_buf):
	out_words = []
	for i in range(0, len(in_buf), 4):
		word = struct.unpack('@I', in_buf[i:i+4])[0]
		out_words.append(struct.pack('@I', bytereverse(word)))
	return ''.join(out_words)

def wordreverse(in_buf):
	out_words = []
	for i in range(0, len(in_buf), 4):
		out_words.append(in_buf[i:i+4])
	out_words.reverse()
	return ''.join(out_words)

class Miner:
	def __init__(self, id):
		self.id = id

	def work(self, datastr, targetstr):
		# decode 80b block from hex string to binary
		static_data = datastr.decode('hex')[:80]
		static_data = bufreverse(static_data)

		# the first 76b of 80b do not change
		blk_hdr = static_data[:76]

		# decode 256-bit target value
		targetbin = targetstr.decode('hex')
		targetbin = targetbin[::-1]	# byte-swap and dword-swap
		targetbin_str = targetbin.encode('hex')
		target = long(targetbin_str, 16)

		hashes_done = 1
		for nonce in xrange(MAX_NONCE):

			# encode 32-bit nonce value
			nonce_bin = struct.pack("<I", nonce)

			# hash final 4b, the nonce value
			hash1_o = hashlib.sha256()
			hash1_o.update(blk_hdr)
			hash1_o.update(nonce_bin)
			hash1 = hash1_o.digest()

			# sha256 hash of sha256 hash
			hash_o = hashlib.sha256()
			hash_o.update(hash1)
			hash = hash_o.digest()

			hashes_done += 1

			# quick test for winning solution: high 32 bits zero?
			H = struct.unpack('<I', hash[28:32])
			if H:
				continue

			# convert binary hash to 256-bit Python long
			hash = bufreverse(hash)
			hash = wordreverse(hash)

			hash_str = hash.encode('hex')
			l = long(hash_str, 16)

			# proof-of-work test:  hash < target
			if l < target:
				print time.asctime(), "PROOF-OF-WORK found: %064x" % (l,)
				return (hashes_done, 
					static_data[:76] + nonce_bin)
			else:
				print time.asctime(), "PROOF-OF-WORK false positive %064x" % (l,)

		return (hashes_done, None)

	def iterate(self, rpc):
		work = rpc.getwork()
		if work is None:
			time.sleep(ERR_SLEEP)
			return
		if 'data' not in work or 'target' not in work:
			time.sleep(ERR_SLEEP)
			return

		time_start = time.time()

		(hashes_done, solution_data) = self.work(work['data'],
							 work['target'])

		time_end = time.time()
		time_diff = time_end - time_start

		if settings['hashmeter']:
			print "HashMeter(%d): %d hashes, %.2f Khash/sec" % (
			      self.id, hashes_done,
			      (hashes_done / 1000.0) / time_diff)

		if solution_data is not None:
			param_arr = [ solution_data ]
			rpc.getwork(param_err)

	def loop(self):
		rpc = BitcoinRPC(settings['host'], settings['port'],
				 settings['rpcuser'], settings['rpcpass'])
		if rpc is None:
			return

		while True:
			self.iterate(rpc)

def miner_thread(id):
	miner = Miner(id)
	miner.loop()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "Usage: poold.py CONFIG-FILE"
		sys.exit(1)

	f = open(sys.argv[1])
	for line in f:
		# skip comment lines
		m = re.search('^\s*#', line)
		if m:
			continue

		# parse key=value lines
		m = re.search('^(\w+)\s*=\s*(\S.*)$', line)
		if m is None:
			continue
		settings[m.group(1)] = m.group(2)
	f.close()

	if 'host' not in settings:
		settings['host'] = '127.0.0.1'
	if 'port' not in settings:
		settings['port'] = 8332
	if 'logdir' not in settings:
		settings['logdir'] = '/var/lib/pool/log'
	if 'threads' not in settings:
		settings['threads'] = 1
	if 'hashmeter' not in settings:
		settings['hashmeter'] = 0
	if 'rpcuser' not in settings or 'rpcpass' not in settings:
		print "Missing username and/or password in cfg file"
		sys.exit(1)

	settings['port'] = int(settings['port'])
	settings['threads'] = int(settings['threads'])
	settings['hashmeter'] = int(settings['hashmeter'])

	thr_list = []
	for thr_id in range(settings['threads']):
		p = Process(target=miner_thread, args=(thr_id,))
		p.start()
		thr_list.append(p)
		time.sleep(1)			# stagger threads

	print settings['threads'], "mining threads started"

	print time.asctime(), "Miner Starts - %s:%s" % (settings['host'], settings['port'])
	try:
		for thr_proc in thr_list:
			thr_proc.join()
	except KeyboardInterrupt:
		pass
	print time.asctime(), "Miner Stops - %s:%s" % (settings['host'], settings['port'])
