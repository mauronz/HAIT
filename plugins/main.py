#!/usr/bin/python

from __future__ import print_function

import copy

from triton import *
from pintool import *

import sys, os

sys.path.append(os.getcwd() + '/plugins/')

from visualization import *

# Global variables
mallocSize = {}
mallocNodes = {}

reallocNodes = {}
reallocPrevAddr = {}

callocNodes = {}
callocNMemb = {}

readAddr = 0
readCount = 0
prevWriteAlloc = None

timeline = [State()]
boundaries = set()

useLibc = True
haveMaps = False

def readMetadata(state) :
	for block in state :
		tmp = getCurrentMemoryValue(block.raddr, 8)
		block.rsize = tmp & (~0xf)
		block.set_flags(tmp & 0xf)
		if isinstance(block, Empty) :
			fd = getCurrentMemoryValue(block.raddr + 8, 8)
			bk = getCurrentMemoryValue(block.raddr + 16, 8)
			block.set_links(fd, bk)

def match_ptr(state, ptr):

    if ptr is None:
        return None, None

    s, smallest_match = None, None

    for i, block in enumerate(state):
        if isinstance(block, Empty) or block.uaddr != ptr:
            continue
        if smallest_match is None or smallest_match.usize >= block.usize:
            s, smallest_match = i, block

    if smallest_match is None:
        state.errors.append("Couldn't find block at %#x, added marker." %
                            (ptr - Block.header))
        # We'll add a small tmp block here to show the error.
        state.append(Marker(ptr, error=True))

    return s, smallest_match

# Reproduce malloc operation.
# If the new block comes from the wilderness just append it
# at the end of the current State;
# otherwise locate the free block that is going to be allocated,
# insert the new block and adjust the free block address and size
# (if the size of the new block is equal to the free block just
# remove it)
def malloc(state, ret, size, controlled=False):

    if not ret:
        state.errors.append("Failed to allocate %#x bytes." % size)
	return None
    else:
	block = Block(ret, size, controlled=controlled)
	index = -1
	for i, b in enumerate(state) :
		if isinstance(b, Empty) and b.raddr == block.raddr :
			index = i

	if index == -1 :
        	state.append(block)
	else :
		free_block = state[index]
		if free_block.rsize > block.rsize :
			free_block.rsize -= block.rsize
			free_block.raddr += block.rsize
			state.insert(index, block)
		else :
			state[index] = block
	return block

# Reproduce calloc operation.
# call malloc of nmemb * size
def calloc(state, ret, nmemb, size, controlled=False):
    return malloc(state, ret, nmemb * size, controlled=controlled)

# Reproduce free operation.
# Find the block to be freed, if none is found add an error.
# If the previous and/or next blocks are also free, merge them.
def free(state, ret, ptr):

    if ptr is 0:
        return

    s, match = match_ptr(state, ptr)

    if match is None:
        return
    elif ret is None:
        state[s] = Block(match.uaddr, match.usize,
                         error=True, color=match.color)
	return None
    else:
	merged = False
	if s != 0 and isinstance(state[s - 1], Empty) :
		prev = state[s - 1]
		prev.rsize += match.rsize
		prev._end += match.rsize
		state.pop(s)
		empty = prev
		merged = True
		s -= 1

	if s != len(state) - 1 and isinstance(state[s + 1], Empty) :
		empty = state[s + 1]
		empty.raddr = match.raddr
		empty.rsize += match.rsize
		state.pop(s)
		merged = True

	if not merged :
        	empty = Empty(match.raddr, match.raddr + match.rsize)
		state[s] = empty

	if isinstance(state[-1], Empty) :
		state.pop(-1)
	
	return empty
		
# Reproduce realloc operation.
# If ptr = 0 call malloc.
# If size = 0 call free.
def realloc(state, ret, ptr, size, controlled=False):

    if not ptr:
        return malloc(state, ret, size, controlled=controlled)
    elif not size:
        return free(state, ret, ptr)

    s, match = match_ptr(state, ptr)

    if match is None:
        return None
    elif ret is None:
        state[s] = Block(match.uaddr, match.usize, color=match.color)
        state[s].error = True
	return None
    else:
	#if the block is enlarged
	if ret == ptr :
             state[s] = Block(ret, size, color=match.color, controlled=controlled)
	     block = state[s]
	#if the block is not the last, we take the next one (which should be free)
	#and shrink it (or delete it if it is completely allocated
	     if len(state) > s + 1 :
	     	next_free = state[s + 1]
		if next_free.rsize > size - match.usize :
			next_free.rsize -= size - match.usize
			next_free.raddr += size - match.usize
		else :
			state.pop(s + 1)
	#if the block is not enlarged, the realloc is equivalent to free of the old 
	#and malloc of the new
	else :
	    free(state, ret, ptr)
	    block = malloc(state, ret, size, controlled=controlled)

	return block

# Create a deep copy of a state
def newState(state) :
	tmp = []
	for b in timeline[-1] :
		cp = copy.deepcopy(b)
		cp.new_id()
		tmp.append(cp)


	state = State(tmp)
	return state


# Perform a recursive DFS traversal of a AST:
# at each step, if the current node is not symbolized stop,
# otherwise, if the node is a symbolic variable, save it;
# finally recur over the children of current node.
# Returns the list of names of the symbolic variables in the AST
def recursiveCheckForSymVars(astNode, curSymbols=None) :

	#if astNode.getKind() != AST_NODE.BV and astNode.getKind() != AST_NODE.EXTRACT and astNode.getKind() != AST_NODE.ZX and astNode.getKind() != AST_NODE.DECIMAL and astNode.getKind() != AST_NODE.BVADD and astNode.getKind() != AST_NODE.SX and astNode.getKind() != AST_NODE.BVMUL and astNode.getKind() != AST_NODE.VARIABLE:
		
	#	for c in AST_NODE.__dict__ :
	#		if AST_NODE.__dict__[c] == astNode.getKind() :
	#			print(c)
	#			break
	#if astNode.getKind() == AST_NODE.VARIABLE :
		#value = astNode.getValue()
		#print(value)

	if curSymbols is None :
		curSymbols = []

	
	if astNode.getKind() == AST_NODE.VARIABLE :
		value = astNode.getValue()
		#print(value)
		if not value in curSymbols :
			curSymbols.append(value)
	else :
		for child in astNode.getChilds():
			recursiveCheckForSymVars(child, curSymbols)

	return curSymbols

def countNodes(astNode) :
	count = 1
	if astNode.isSymbolized() :
		for child in astNode.getChilds():
			count += countNodes(child)

	return count
	

# Prints the names and comments of the symbolic variables int the list
def printSymVars(symbols) :
	for name in symbols :
		symbol = getSymbolicVariableFromName(name)
		print('\t%s %s' % (name, symbol.getComment()))
		

# Main entry callback :
# performs the symbolization of the command-line arguments
def callback_main_entry(threadId):
	rdi = getCurrentRegisterValue(REG.RDI) # argc
	rsi = getCurrentRegisterValue(REG.RSI) # argv

	for i in range(1, rdi) :
		addr = getCurrentMemoryValue(rsi + 8 * i, CPUSIZE.QWORD)      # argv[x] pointer
		
		size = 0
		value = getCurrentMemoryValue(addr, 1)
		while value != 0 :
			mem = Memory(addr + size, 1)
			comment = 'argv[' + str(i) + '][' + str(size) + ']'
			symVar = convertMemoryToSymbolicVariable(mem, comment)
			size += 1
			value = getCurrentMemoryValue(addr + size, 1)

		#coarse tracing
		#mem = Memory(addr, size)
		#symVar = convertMemoryToSymbolicVariable(mem)	


def callback_read_entry(threadId):
	global readAddr

	rdi = getCurrentRegisterValue(REG.RDI)
	if rdi == 0:
		readAddr = getCurrentRegisterValue(REG.RSI)
		 #print('\n[*] Input required: ')
		#print "%x" % (readAddr)


# Read exit callback:
# performs the symbolization of standard input.
# The read function is just a wrapper that executes a syscall;
# the code in the syscall is executed in a different context so
# Triton instruction callbacks do not work there. This means that
# we need to call check_write_alloc in this callback.
def callback_read_exit(threadId):
	global readAddr
	global readCount
	global useLibc

	size = getCurrentRegisterValue(REG.RAX)
	print('[*] Read %d bytes' % (size))
	readCount += 1
	if readAddr != 0 :

		check_write_alloc(readAddr, size)	

		if useLibc :
			#fine tracing
			for i in range(0, size) :
				mem = Memory(readAddr + i, 1)
				comment = 'read #%d byte %d' % (readCount, i)
				convertMemoryToSymbolicVariable(mem, comment)

		#coarse tracing
		#mem = Memory(readAddr, size)
		#convertMemoryToSymbolicVariable(mem, 'read %d size %d' % (readCount, size))
		
		readAddr = 0

#-------------------------------------------------------------------------------------------------------

# *alloc callbacks general procedure:
# entry : get the parameters' full AST, if it is symbolized save it in a global variable
# exit  : if the AST is symbolized retrieve the symbolic variables in it;
#         create a new state, add it to the timeline, reproduce the heap operation by calling the function;
#         generate the html output.

def callback_malloc_entry(threadId):
	global mallocNodes
	global mallocSize
	global useLibc

	mallocSize[threadId] = getCurrentRegisterValue(REG.RDI)

	if useLibc :
		rdiId = getSymbolicRegisterId(REG.RDI)
		astNode = getFullAstFromId(rdiId)

	#c = countNodes(astNode)
	#print('[*] nodes = %d' % (c))
		#print(astNode)

		if astNode.isSymbolized() :
			mallocNodes[threadId] = astNode
			concretizeAllRegister()

#-------------------------------------------------------------------------------------------------------

def callback_malloc_exit(threadId):
	global mallocNodes
	global timeline
	global boundaries
	global mallocSize
	global useLibc

	controlled = False

	addr = getCurrentRegisterValue(REG.RAX)
	tmpsize = getCurrentMemoryValue(addr - 8, CPUSIZE.QWORD)
	rsize = tmpsize & (~0xf)
	usize = mallocSize[threadId]

	print('[*] Malloc -> addr = %x, usize = 0x%x, rsize = 0x%x' % (addr, usize, rsize))
	if threadId in mallocNodes :
		controlled = True
		node = mallocNodes[threadId]
		symbols = recursiveCheckForSymVars(node)
		printSymVars(symbols)
		mallocNodes.pop(threadId, None)
		
	print('---------------------------------------')
	
	
	state = newState(timeline[-1])

	block = malloc(state, addr, usize, controlled=controlled) 
	block.set_flags(tmpsize & 0xf)
	boundaries.update(state.boundaries())
	timeline.append(state)

	if not useLibc :
		readMetadata(state)
	
	out = open('/tmp/out.html', 'w')
	gen_html(timeline, boundaries, out)
	out.close()
	
#-----------------------------------------------------------------------------------------------------------

def callback_realloc_entry(threadId):
	global reallocNodes
	global mallocSize
	global reallocPrevAddr
	global useLibc

	
	reallocPrevAddr[threadId] = getCurrentRegisterValue(REG.RDI)
	mallocSize[threadId] = getCurrentRegisterValue(REG.RSI)

	try :
		if useLibc :
			rdiId = getSymbolicRegisterId(REG.RDI)
			rdiNode = getFullAstFromId(rdiId)
			if not rdiNode.isSymbolized() :
				rdiNode = None

			rsiId = getSymbolicRegisterId(REG.RSI)
			rsiNode = getFullAstFromId(rsiId)
			if not rsiNode.isSymbolized() :
				rsiNode = None

			reallocNodes[threadId] = (rdiNode, rsiNode)
			concretizeAllRegister()
	
	except :
		pass
 
#----------------------------------------------------------------------------------------------------------

def callback_realloc_exit(threadId):
	global reallocNodes
	global reallocPrevAddr
	global timeline
	global boundaries
	global mallocSize
	global useLibc

	controlled = False

	addr = getCurrentRegisterValue(REG.RAX)
	tmpsize = getCurrentMemoryValue(addr - 8, CPUSIZE.QWORD)
	rsize = tmpsize & (~0xf)
	usize = mallocSize[threadId]

	print('[*] Realloc -> addr = %x, usize =  0x%x, rsize = 0x%x (prev block = %x)' % (addr, usize, rsize, reallocPrevAddr[threadId]))

	if not reallocNodes[threadId][0] is None :
		controlled = True
		print('[*] Input address depends on:')
		node = reallocNodes[threadId][0]
		symbols = recursiveCheckForSymVars(node)
		printSymVars(symbols)

	if not reallocNodes[threadId][1] is None :
		controlled = True
		print('\n[*] New size depends on:')
		node = reallocNodes[threadId][1]
		symbols = recursiveCheckForSymVars(node)
		printSymVars(symbols)
	print('---------------------------------------')

	reallocNodes.pop(threadId, None)
	
	state = newState(timeline[-1])

	block = realloc(state, addr, reallocPrevAddr[threadId], usize, controlled=controlled)
	block.set_flags(tmpsize & 0xf)
	boundaries.update(state.boundaries())
	timeline.append(state)

	if not useLibc :
		readMetadata(state)
	
	out = open('/tmp/out.html', 'w')
	gen_html(timeline, boundaries, out)
	out.close()
	
#--------------------------------------------------------------------------------------------------------	

def callback_calloc_entry(threadId):
	global callocNodes
	global mallocSize
	global callocNMemb
	global useLibc

	callocNMemb[threadId] = getCurrentRegisterValue(REG.RDI)
	mallocSize[threadId] = getCurrentRegisterValue(REG.RSI)

	try :
		if useLibc :
			rdiId = getSymbolicRegisterId(REG.RDI)
			rdiNode = getFullAstFromId(rdiId)
			if not rdiNode.isSymbolized() :
				rdiNode = None

			rsiId = getSymbolicRegisterId(REG.RSI)
			rsiNode = getFullAstFromId(rsiId)
			if not rsiNode.isSymbolized() :
				rsiNode = None

			callocNodes[threadId] = (rdiNode, rsiNode)		
			concretizeAllRegister()
	
	except :
		pass
 

#--------------------------------------------------------------------------------------------------------

def callback_calloc_exit(threadId):
	global callocNodes
	global callocNMemb
	global timeline
	global boundaries
	global mallocSize
	global useLibc

	controlled = False

	addr = getCurrentRegisterValue(REG.RAX)
	tmpsize = getCurrentMemoryValue(addr - 8, CPUSIZE.QWORD)
	rsize = tmpsize & (~0xf)
	usize = mallocSize[threadId] * callocNMemb[threadId]

	print('[*] Calloc -> addr = %x, usize =  0x%x, rsize = 0x%x ' % (addr, usize, rsize))

	if not callocNodes[threadId][0] is None :
		controlled = True
		print('[*] NMemb depends on:')
		node = reallocNodes[threadId][0]
		symbols = recursiveCheckForSymVars(node)
		printSymVars(symbols)

	if not callocNodes[threadId][1] is None :
		controlled = True
		print('\n[*] Memb size depends on:')
		node = reallocNodes[threadId][1]
		symbols = recursiveCheckForSymVars(node)
		printSymVars(symbols)
	print('---------------------------------------')

	callocNodes.pop(threadId, None)
	
	state = newState(timeline[-1])

	block = calloc(state, addr, callocNMemb[threadId], usize, controlled=controlled)
	block.set_flags(tmpsize & 0xf)
	boundaries.update(state.boundaries())
	timeline.append(state)

	if not useLibc :
		readMetadata(state)
	
	out = open('/tmp/out.html', 'w')
	gen_html(timeline, boundaries, out)
	out.close()	

#--------------------------------------------------------------------------------------------------

# Free entry callback:
# identical to *alloc, but everything is performed here
# because, for some reason, Triton cannot hook the exit of free
def callback_free_entry(threadId):
	global timeline
	global boundaries

	rdi = getCurrentRegisterValue(REG.RDI)
	print('[*] Free -> addr = %x' % (rdi))
	print('---------------------------------------')

	state = newState(timeline[-1])

	empty = free(state, 0, rdi)
	
	boundaries.update(state.boundaries())
	timeline.append(state)
	
	out = open('/tmp/out.html', 'w')
	gen_html(timeline, boundaries, out)
	out.close()

#--------------------------------------------------------------------------------------------------------------	

# ato* and strlen entry callback general procedure:
# for each byte of the string parameter get the full AST,
# and for each symbolic variable in it log its "passing through" the function

def logStringToNumberFunction(addr, functionName) :
	while getCurrentMemoryValue(addr) != 0:
		memId = getSymbolicMemoryId(addr)
		astNode = getFullAstFromId(memId)
		if astNode.isSymbolized() :
			names = recursiveCheckForSymVars(astNode)
			for name in names :
				symVar = getSymbolicVariableFromName(name)
				comment = symVar.getComment()
				if comment.find(functionName) < 0 :
					symVar.setComment(comment + ' -> ' + functionName)

		addr += 1
#--------------------------------------------------------------------------------------------------------------

# ato* and strlen entry callbacks 

def callback_atoi_entry(threadId) :
	addr = getCurrentRegisterValue(REG.RDI)
	logStringToNumberFunction(addr, 'atoi')

#--------------------------------------------------------------------------------------------------------------

def callback_atol_entry(threadId) :
	addr = getCurrentRegisterValue(REG.RDI)
	logStringToNumberFunction(addr, 'atol')

#--------------------------------------------------------------------------------------------------------------

def callback_atoll_entry(threadId) :
	addr = getCurrentRegisterValue(REG.RDI)
	logStringToNumberFunction(addr, 'atoll')
			
#--------------------------------------------------------------------------------------------------------------	

def callback_strlen_entry(threadId) :
	addr = getCurrentRegisterValue(REG.RDI)
	logStringToNumberFunction(addr, 'strlen')

#--------------------------------------------------------------------------------------------------------------

# callback after each instruction
# if the instruction consists of a memory write
# get the destination address and the size of the value
# and call check_write_alloc 
def callback_after(instr) :
	global haveMaps
	global boundaries

	if not haveMaps:
		getMaps()
		haveMaps = True

	#print('%x' % instr.getAddress())

	#freenote : 400a3d
	#stkof : 400c6f

	
	if instr.getAddress() == 0x400a3d :
		reg = Register(REG.RDI, 0)
		setCurrentRegisterValue(reg)
		concretizeRegister(REG.RDI)

	elif instr.isMemoryWrite() :
		#for c in OPCODE.__dict__ :
		#	if OPCODE.__dict__[c] == instr.getType() :
		#		print(c)
		#		break

		addr = None
		size = None
		for op in instr.getOperands() :
			if op.getType() == OPERAND.MEM :	
				addr = op.getAddress()	
			else :
				size = op.getSize()
		if not addr is None and not size is None :
			check_write_alloc(addr, size)

#--------------------------------------------------------------------------------------------------------------

# Checks if a memory write (given address and size)
# occurs in the heap, in particular if it writes the metadata
# of a chunk, either the flags, the chunk size or the links of
# a free chunk. Keep track of the last write operation, so that
# we can distinguish a continued write
def check_write_alloc(addr, size) :
	global timeline
	global prevWriteAlloc

	for block in timeline[-1] :
		if addr >= block.raddr and addr < block.raddr + block.rsize :
			if not prevWriteAlloc is None and prevWriteAlloc[0] == block.raddr and prevWriteAlloc[1] + prevWriteAlloc[2] == addr :

				prevAddr = prevWriteAlloc[1]
				prevSize = prevWriteAlloc[2]

				sys.stdout.write("\033[F") # cursor up one line to overwrite the previous
				print('[*] Continued write operation in block %x, starting at %x (current size 0x%x)' % (block.raddr, prevAddr, prevSize + size))
			
			else :
				#if block.type == AllocBlock.ALLOCATED :
				print('[*] Write operation in block %x, at %x (size 0x%x) %x' % (block.raddr, addr, size, getCurrentMemoryValue(addr, size)))				
				#else :
				#	print('[*] Write operation in freed block %x, at %x (size 0x%x)' % (block.raddr, addr, size))

				prevSize = 0
				prevAddr = addr

			if addr < block.raddr + 8 :
				val = getCurrentMemoryValue(block.raddr, 8)
				block.rsize = val & (~0xf)
				block.set_flags(val & 0xf)
				print('[*] Overwriting the chunk header! size=0x%x prev_inuse=%d is_mmapped=%d non_main_arena=%d' % (block.rsize, block.prev_inuse, block.is_mmapped, block.non_main_arena))


			elif addr == block.raddr + 8 and isinstance(block, Empty) :
				val = getCurrentMemoryValue(block.raddr + 8, 8)
				print('[*] new fd link : %x' % (val))
				block.fd = val

			elif addr == block.raddr + 16 and isinstance(block, Empty) :
				val = getCurrentMemoryValue(block.raddr + 16, 8)
				print('[*] new bk link : %x' % (val))
				block.bk = val

			
			prevWriteAlloc = (block.raddr, prevAddr, prevSize + size)

			bounds = sorted(list(boundaries))
			width = -1
			for b in bounds :
				if addr > b :
					width += 1
			out = open('/tmp/out.html', 'w')
			write_op = '<div><strong style="padding-left: %dem;;">' % (10 * width)
			write_op += '0x%x</strong>' % (addr)
			write_op += '</div>'

			gen_html(timeline, boundaries, out, write_op = write_op)

			out.close()

#--------------------------------------------------------------------------------------------------------------
def getMaps():
	maps = open('/proc/' + str(os.getpid()) + '/maps', 'r')
	line = maps.readline()
	res = 'No libc detected!'
	while len(line) > 0 :
		if line.find('libc') != -1 :
			res = ''
			break
		line = maps.readline()

	for i in range(0,4):
		split = line.split(' ')
		res += split[0] + ' ' + split[1] + ' ' + split[-1]
		line = maps.readline()

	maps.close()
	
	set_maps(res)	


#--------------------------------------------------------------------------------------------------------------

if __name__ == '__main__' :

	random.seed(226)

	setArchitecture(ARCH.X86_64)

	choice = raw_input('Blacklist libc? [Y/N] This greatly speeds up the execution, but does not allow input tracing (default=N): ')
	useLibc = (choice.upper() != 'Y' and choice.upper() != 'YES')

	if useLibc :
		addCallback(callback_main_entry, CALLBACK.ROUTINE_ENTRY, 'main')

		addCallback(callback_atoi_entry, CALLBACK.ROUTINE_ENTRY, 'atoi')
		addCallback(callback_atol_entry, CALLBACK.ROUTINE_ENTRY, 'atol')
		addCallback(callback_atoll_entry, CALLBACK.ROUTINE_ENTRY, 'atoll')
	else :
		setupImageBlacklist(['libc.so.6'])


	addCallback(callback_malloc_entry, CALLBACK.ROUTINE_ENTRY, 'malloc')
	addCallback(callback_malloc_exit, CALLBACK.ROUTINE_EXIT, 'malloc')

	addCallback(callback_realloc_entry, CALLBACK.ROUTINE_ENTRY, 'realloc')
	addCallback(callback_realloc_exit, CALLBACK.ROUTINE_EXIT, 'realloc')


	addCallback(callback_calloc_entry, CALLBACK.ROUTINE_ENTRY, 'calloc')
	addCallback(callback_calloc_exit, CALLBACK.ROUTINE_EXIT, 'calloc')

	addCallback(callback_free_entry, CALLBACK.ROUTINE_ENTRY, 'free')
	
	addCallback(callback_read_entry, CALLBACK.ROUTINE_ENTRY, 'read')
	addCallback(callback_read_exit, CALLBACK.ROUTINE_EXIT, 'read')

	addCallback(callback_after, CALLBACK.AFTER)

	#enableSymbolicOptimization(OPTIMIZATION.AST_DICTIONARIES, True)

	#enableSymbolicZ3Simplification(True)

	startAnalysisFromEntry()
	runProgram()
