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
import http.client
import sys
import configparser
import plac
from multiprocessing import Process

ERR_SLEEP = 15
MAX_NONCE = 1000000

settings = {}
pp = pprint.PrettyPrinter(indent=4)


class BitcoinRPC:
    uid = 1

    def __init__(self, host, port, username, password):
        auth_pair = "%s:%s" % (username, password)
        self.auth_hdr = "Basic %s" % (base64.b64encode(auth_pair))
        self.conn = http.client.HTTPConnection(host, port, False, 30)

    def rpc(self, method, params=None):
        self.uid += 1
        obj = {
            'version': '1.1',
            'method': method,
            'id': self.uid
        }
        if params is None:
            obj['params'] = []
        else:
            obj['params'] = params
        self.conn.request('POST', '/', json.dumps(obj),
                          {
                              'Authorization': self.auth_hdr,
                              'Content-type': 'application/json'
                          })

        resp = self.conn.getresponse()
        if resp is None:
            print("JSON-RPC: no response")
            return None

        body = resp.read()
        resp_obj = json.loads(body)
        if resp_obj is None:
            print("JSON-RPC: cannot JSON-decode body")
            return None
        if 'error' in resp_obj and resp_obj['error'] is not None:
            return resp_obj['error']
        if 'result' not in resp_obj:
            print("JSON-RPC: no result in object")
            return None

        return resp_obj['result']

    def get_block_count(self):
        return self.rpc('getblockcount')

    def get_work(self, data=None):
        return self.rpc('getwork', data)


def uint32(x):
    return x & 0xffffffff


def byte_reverse(x):
    return uint32(((x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24)))


def buf_reverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        word = struct.unpack('@I', in_buf[i:i + 4])[0]
        out_words.append(struct.pack('@I', byte_reverse(word)))
    return ''.join(out_words)


def word_reverse(in_buf):
    out_words = []
    for i in range(0, len(in_buf), 4):
        out_words.append(in_buf[i:i + 4])
    out_words.reverse()
    return ''.join(out_words)


class Miner:
    def __init__(self, id, config):
        self.id = id
        self.config = config
        self.max_nonce = MAX_NONCE

    def work(self, data_str, target_str):
        # decode work data hex string to binary
        static_data = data_str.decode('hex')
        static_data = buf_reverse(static_data)

        # the first 76b of 80b do not change
        blk_hdr = static_data[:76]

        # decode 256-bit target value
        target_bin = target_str.decode('hex')
        target_bin = target_bin[::-1]  # byte-swap and dword-swap
        target_bin_str = target_bin.encode('hex')
        target = int(target_bin_str, 16)

        # pre-hash first 76b of block header
        static_hash = hashlib.sha256()
        static_hash.update(blk_hdr)

        for nonce in range(self.max_nonce):

            # encode 32-bit nonce value
            nonce_bin = struct.pack("<I", nonce)

            # hash final 4b, the nonce value
            hash1_o = static_hash.copy()
            hash1_o.update(nonce_bin)
            hash1 = hash1_o.digest()

            # sha256 hash of sha256 hash
            hash_o = hashlib.sha256()
            hash_o.update(hash1)
            hash_bin = hash_o.digest()

            # quick test for winning solution: high 32 bits zero?
            if hash_bin[-4:] != '\0\0\0\0':
                continue

            # convert binary hash to 256-bit Python long
            hash_bin = buf_reverse(hash_bin)
            hash_bin = word_reverse(hash_bin)

            hash_str = hash_bin.encode('hex')
            l = int(hash_str, 16)

            # proof-of-work test:  hash < target
            if l < target:
                print(time.asctime(), "PROOF-OF-WORK found: %064x" % (l,))
                return nonce + 1, nonce_bin
            else:
                print(time.asctime(), "PROOF-OF-WORK false positive %064x" % (l,))
                # return (nonce + 1, nonce_bin)

        return nonce + 1, None

    @staticmethod
    def submit_work(rpc, original_data, nonce_bin):
        nonce_bin = buf_reverse(nonce_bin)
        nonce = nonce_bin.encode('hex')
        solution = original_data[:152] + nonce + original_data[160:256]
        param_arr = [solution]
        result = rpc.get_work(param_arr)
        print(time.asctime(), "--> Upstream RPC result:", result)

    def iterate(self, rpc):
        work = rpc.get_work()
        if work is None:
            time.sleep(ERR_SLEEP)
            return
        if 'data' not in work or 'target' not in work:
            time.sleep(ERR_SLEEP)
            return

        time_start = time.time()

        (hashes_done, nonce_bin) = self.work(work['data'],
                                             work['target'])

        time_end = time.time()
        time_diff = time_end - time_start

        self.max_nonce = int(
            (hashes_done * settings['scan_time']) / time_diff)
        if self.max_nonce > 0xfffffffa:
            self.max_nonce = 0xfffffffa

        if settings['hash_meter']:
            print("hash_meter(%d): %d hashes, %.2f Khash/sec" % (
                self.id, hashes_done,
                (hashes_done / 1000.0) / time_diff))

        if nonce_bin is not None:
            self.submit_work(rpc, work['data'], nonce_bin)

    def loop(self):
        rpc = BitcoinRPC(self.config['server']['host'], self.config['server']['port'],
                         settings['rpc_user'], settings['rpc_pass'])
        if rpc is None:
            return

        while True:
            self.iterate(rpc)


def miner_thread(uid, config):
    miner = Miner(uid, config)
    miner.loop()


def main(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    if 'login' not in config:
        print('login required')
    elif 'user' not in config['login']:
        print('user required')
    elif 'user' not in config['login']:
        print('pass required')

    """
    if 'host' not in settings:
        settings['host'] = '127.0.0.1'
    if 'port' not in settings:
        settings['port'] = 8332
    if 'threads' not in settings:
        settings['threads'] = 1
    if 'hash_meter' not in settings:
        settings['hash_meter'] = 0
    if 'scan_time' not in settings:
        settings['scan_time'] = 30
    if 'rpc_user' not in settings or 'rpc_pass' not in settings:
        print("Missing username and/or password in cfg file")
        sys.exit(1)
    """

    thr_list = []
    for thr_id in range(config['mining'].getint(['threads'])):
        p = Process(target=miner_thread, args=(thr_id, config))
        p.start()
        thr_list.append(p)
        time.sleep(1)  # stagger threads

    print(config['mining']['threads'], "mining threads started")

    print(time.asctime(), "Miner Starts - %s:%s" % (config['server']['host'], config['server']['port']))
    try:
        for thr_proc in thr_list:
            thr_proc.join()
    except KeyboardInterrupt:
        pass
    print(time.asctime(), "Miner Stops - %s:%s" % (config['server']['host'], config['server']['port']))


if __name__ == '__main__':
    try:
        plac.call(main)
    except KeyboardInterrupt:
        print('\nGoodbye!')
