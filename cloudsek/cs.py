#!/usr/bin/env python

challenge = "649f765af7b17bddd37a3bc0cb24e47dbb8418f655ff858885fb10b7eae4a1daf6621941f75aad73"
challenge_hex = "\x64\x9f\x76\x5a\xf7\xb1\x7b\xdd\xd3\x7a\x3b\xc0\xcb\x24\xe4\x7d\xbb\x84\x18\xf6\x55\xff\x85\x88\x85\xfb\x10\xb7\xea\xe4\xa1\xda\xf6\x62\x19\x41\xf7\x5a\xad\x73"


def xor(msg, key):
  return "".join([chr(ord(c) ^ key) for c in msg])


def test1():
  for i in range(128):
    msg = xor(challenge_hex, i)
    print "i: %d, c: %c, out: \"%s\"" % (i, chr(i), msg)
    msg = xor(msg, i)
    print "i: %d, c: %c, out: \"%s\"" % (i, chr(i), msg)
  print

if __name__ == "__main__":
  test1()

