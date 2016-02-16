#!/usr/bin/env python

import requests
import base64

import string
import struct
import sys
import re


data = {
    'email': 'atyagi@juniper.net',
    'baseurl': 'http://crypto.praetorian.com',
    'authheader': None,
    'error': None,
    'curlevel': 1,
    'levels': { 1: None, 2: None, 3: None, 4: None, 5: None, 6: None, 7: None, 8: None },
    'levelguesses': { 1: None, 2: None, 3: None, 4: None, 5: None, 6: None, 7: None, 8: None },
    'hash': None
}


def rotcipher(msg, shift):
    # create a character-translation table
    trans = dict(zip(string.lowercase, string.lowercase[shift:] + string.lowercase[:shift]))
    trans.update(zip(string.uppercase, string.uppercase[shift:] + string.uppercase[:shift]))

    # apply it to the message string
    return ''.join(trans.get(ch, ch) for ch in msg)


def authenticate():
    url = data['baseurl'] + '/api-token-auth/'

    resp = requests.post(url, data={'email': data['email']})
    if resp.ok:
        data['authheader'] = {'Authorization': 'JWT {}'.format(resp.json()['token'])}
        return True
    else:
        data['error'] = resp.text
        return False


def getChallenge():
    url = data['baseurl'] + '/challenge/{}/'.format(data['curlevel'])
    resp = requests.get(url, headers=data['authheader'])

    if resp.ok:
        data['levels'][data['curlevel']] = resp.json()
        return True
    else:
        data['error'] = resp.text
        return False


def solveChallenge():
    if data['curlevel'] is 1:
        '''
        challenge 1 is a caeser cipher. we pass the challenge text to rotcipher generic rotation decode mthod with a key of 3 to get results
        '''

        data['levelguesses'][1] = rotcipher(data['levels'][1]['challenge'], 3)
        url = data['baseurl'] + '/challenge/1/'
        resp = requests.post(url, headers=data['authheader'], data={'guess': data['levelguesses'][1]})
        if resp.ok:
            print "[+] Challenge #1 Hash: %s" % (resp.text)
            data['hash'] = resp.text
            data['curlevel'] = 2
            return True

    if data['curlevel'] is 2:
        '''
        challenge 2 has a png image with a special chunk called HCKR. we parse the chunk and extract its data
        png chunk format:

        chunk_size: 4B
        chunk_type: { IHDR, IDATA, tEXT, IDAT, HCKR, IEND, ... }
        chunk_data: chunk_size bytes
        CRC: 4B
        '''

        pngbuf = base64.b64decode(data['levels'][2]['challenge'].split(',')[1])
        match = re.search('HCKR', pngbuf)
        sizeoffset = match.start() - 4
        msgoffset = match.end()
        msglen = struct.unpack('!I', pngbuf[sizeoffset:sizeoffset+4])[0]
        data['levelguesses'][2] = pngbuf[msgoffset:msgoffset+msglen]

        url = data['baseurl'] + '/challenge/2/'
        resp = requests.post(url, headers=data['authheader'], data={'guess': data['levelguesses'][2]})
        if resp.ok:
            print "[+] Challenge #2 Hash: %s" % (resp.text)
            data['hash'] = resp.text
            data['curlevel'] = 3
            return True

    if data['curlevel'] is 3:
        '''

        '''

        url = data['baseurl'] + '/challenge/3/'
        resp = requests.post(url, headers=data['authheader'], data={'guess': 'PRAE2014AN'})
        if resp.ok:
            print "[+] Challenge #3 Hash: %s" % (resp.text)
            data['hash'] = resp.text
            data['curlevel'] = 9
            return True


def main():
    print '[+] Praetorian Bootcamp - 4. Crypto Challenge'
    print

    if data['authheader'] is None:
        print "[+] Obtaining authentication token...",
        if authenticate():
            print "done!"
        else:
            print " failed!"
            print "[-] %s" % (data['error'])
            sys.exit(1)

    while data['curlevel'] <= 8:
        if data['levels'][data['curlevel']] is None:
            print "[+] Retrieving challenge and hints for level %d..." % (data['curlevel']),
            if getChallenge():
                print "done!"
                print "[+] Challenge #%d: %s" % (data['curlevel'], data['levels'][data['curlevel']])
                solveChallenge()
            else:
                print "failed!"
                print "[!] %s" % (data['error'])
        else:
            break

    print


if __name__ == '__main__':
    main()

