#!/usr/bin/env python

kases = int(raw_input())
kasestring = raw_input()
kaselist = []

for kase in kasestring.split(' ', kases):
	kaselist.append(int(kase))

for kase in kaselist:
	for kaseout in range(1, kase+1):
		if kaseout % 15 == 0:
			print 'FizzBuzz'
		elif kaseout % 3 == 0:
			print 'Fizz'
		elif kaseout % 5 == 0:
			print 'Buzz'
		else:
			print kaseout
