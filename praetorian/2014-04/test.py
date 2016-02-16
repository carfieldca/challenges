#!/usr/bin/env python

import sys
import string

import string

def caesar_cipher(msg, shift):
    # create a character-translation table
    trans = dict(zip(string.lowercase, string.lowercase[shift:] + string.lowercase[:shift]))
    trans.update(zip(string.uppercase, string.uppercase[shift:] + string.uppercase[:shift]))

    # apply it to the message string
    return ''.join(trans.get(ch, ch) for ch in msg)

def main(infile):
	f = open(infile)

	for line in f.readlines():
		print caesar_cipher(line, -7)

	f.close()

if __name__ == "__main__":
	main(sys.argv[1])
