#!/usr/bin/env python

import os, sys, mmap, re, hashlib, base64, requests
from bs4 import BeautifulSoup

conf = {}
params = {}


# download and save a file
def das(baseurl, filename):
	resp = requests.get("%s/%s" % (baseurl, filename), verify=False)
	if not resp.ok:
		print("[-] Download failed! Exiting.")
		sys.exit(1)
	else:
		with open(filename, 'wb') as f:
			for chunk in resp.iter_content(1024):
				f.write(chunk)
		f.close()


# xtract string matching regexp from a file
def xtractNonce(filetosearch, regexp, adj):
	f = open(filetosearch, 'r+b')
	m = mmap.mmap(f.fileno(), 0)
	m.seek(0)
	rt = re.compile(regexp)
	r = re.search(rt, m)
	f.seek(r.start() + adj)
	srvstr = f.read(r.end() - r.start() - adj)

	m.close()
	f.close()

	return srvstr


# submit post request and extract key
def getStage2(stage1url, stage1phpfile, params):
	resp = requests.post("%s/%s" % (stage1url, stage1phpfile), params)
	s = BeautifulSoup(resp.text)
	r = str(s.find_all('blockquote')[0])
	return r.replace('<blockquote>', '').replace('<br/>', '').replace('</blockquote>', '')


# solve server challenge and extract regcode + 128B regkey
def solveStage2(decodedstr):
	regcode, regkey = None, None

	m = re.search('\d{5}', decodedstr)
	regcode = decodedstr[m.start():m.end()]

	m = re.search('done! : .*', decodedstr)
	querykey = decodedstr[m.start()+8:m.end()]

	cleanupcli = "rm -rf ./shellcode.raw ./shellcode.s ./shellcode.o ./shellcode ./trace.gdb >/dev/null"
	os.popen(cleanupcli)

	fo = open("./shellcode.raw", 'w')
	fo.write(querykey.replace('\\x', '').decode('hex'))
	fo.close()

	shellcodeheader = """global _start

_start:
"""

	ndisasmcli = "ndisasm -b32 ./shellcode.raw | grep -oP '\s{8}[^\s]+.*'"
	ndisasout = os.popen(ndisasmcli).read()
	ndisasout = ndisasout.replace("        lodsb", "jmplabel:\n        lodsb")
	ndisasout = ndisasout.replace("loop 0xb7", "loop jmplabel")
	fo = open("./shellcode.s", 'w')
	fo.write(shellcodeheader + ndisasout)
	fo.close()

	fo = open("./shellcode.s", 'r')
	linecount = len(fo.readlines())
	fo.close()

	os.popen("nasm -f elf -o ./shellcode.o ./shellcode.s -g")
	os.popen("ld -m elf_i386 -o ./shellcode ./shellcode.o")

	tracescript = """b %d
r
x /10s $esp
c
q
""" % (linecount - 1)

	fo = open("./trace.gdb", 'w')
	fo.write(tracescript)
	fo.close()

	regkey = os.popen("gdb -q ./shellcode -x trace.gdb | grep -oP '0x[a-fA-F0-9]{8}:\s+\x22[^\x22]{128}\x22' | grep -oP '[^\s\x22]{128}'").read().strip()

	return regcode, regkey


def main():
	conf['stage1url'] = "http://www.fc4.me"
	conf['stage1file'] = "index.php"
	conf['stage1jsfile'] = "fc4.js"
	conf['stage1phpfile'] = "fc4me.php"

	print("\n[+] Downloading stage1 webpage %s/%s ..." % (conf['stage1url'], conf['stage1file'])),
	das(conf['stage1url'], conf['stage1file'])
	print("done.")

	print("[+] Extracting srvstr for %s ..." % (conf['email'])),
	conf['querystr2'] = xtractNonce(conf['stage1file'], r"var srvstr='[^']+", 12)
	print("\'%s\'" % (conf['querystr2']))

	print("\n[+] Downloading stage1 js file %s/%s ..." % (conf['stage1url'], conf['stage1jsfile'])),
	das(conf['stage1url'], conf['stage1jsfile'])
	print("done.")

	print("[+] Extracting query string ..."),
	conf['querystr1'] = xtractNonce(conf['stage1jsfile'], r"hexMD5\x28\x22[^\x22]+", 8).replace("\\x", "").decode('hex')
	print("\'%s\'" % conf['querystr1'])

	conf['stage1query'] = "%s%s" % (conf['querystr1'], conf['querystr2'])
	print("\n[+] Stage1 security string is \'%s\'" % (conf['stage1query']))

	print("[+] Calculating hexMD5 ..."),
	conf['stage1key'] = hashlib.md5(conf['stage1query']).hexdigest()
	print("%s" % (conf['stage1key']))

	print("\n[+] Submitting post request to %s/%s" % (conf['stage1url'], conf['stage1phpfile']))
	params['email'] = conf['email']
	params['securitystring'] = conf['stage1key']
	conf['querystr3'] = getStage2(conf['stage1url'], conf['stage1phpfile'], params)
	print("[+] Found a %dB query string for stage2" % (len(conf['querystr3'])))

	print("\n[+] Performing Base64 decode on stage2 query str ..."),
	decodedstr = base64.b64decode(conf['querystr3'])
	print("done.")
	print("%s" % (decodedstr))

	print("\n[+] Extracting regcode and regkey from decoded string ...")
	regcode, regkey = solveStage2(decodedstr)
	print("[+] Found regcode: %s" % regcode)
	print("[+] Found regkey (%dB): %s" % (len(regkey), regkey))
	print


if __name__ == "__main__":
	if len(sys.argv) == 2:
		conf['email'] = sys.argv[1]
	else:
		conf['email'] = "7h3rAm@gmail.com"

	main()
