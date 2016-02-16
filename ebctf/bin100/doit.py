#!/usr/bin/env python2

import sys
from pwn import *

e = ELF('bin100')

addrvals = {
  0x08048ee1: 0x03,
  0x080490ee: 0x01,
  0x080492fc: 0x03,
  0x080494ff: 0x03,
  0x08049744: 0x07
}
for addr, value in addrvals.iteritems():
  print "0x%08x" % (addr)
  e.write(addr, asm("mov DWORD PTR [esp+0x50], %s" % (value), arch="i386"))
  print disasm(e.read(addr-0xf, 32))
  print

e.save('bin100.patched')
