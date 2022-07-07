import binascii
from math import ceil
import time
import os
from random import choice
xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))
rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)
get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))
put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]
padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]
unpadding = lambda data: data[:-data[-1]]
list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])
bytes_to_list = lambda data: [i for i in data]
random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])
IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]

def sm3_ff_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret

def sm3_gg_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret

def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))

def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))

def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4,(i+1)*4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "%08x" % w[j]
    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "%08x" % w_1[j]

    a, b, c, d, e, f, g, h = v_i

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
            e +
            (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]

def sm3_hash(msg):
    #print(msg)
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])

    group_count = round(len(msg) / 64)

    B = []
    for i in range(0, group_count):
        B.append(msg[i*64:(i+1)*64])

    V = []
    V.append(IV)
    for i in range(0, group_count):
        V.append(sm3_cf(V[i], B[i]))

    y = V[i+1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result

def sm3_kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen/32)
    zin = [i for i in bytes.fromhex(z.decode('utf8'))]
    ha = ""
    for i in range(rcnt):
        msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
        ha = ha + sm3_hash(msg)
        ct += 1
    return ha[0: klen * 2]

def sm3_gmssl(data: bytes) -> bytes:
    return bytes.fromhex(sm3_hash([i for i in data]))

def sm3_gmssl_hex(data) -> bytes: #用于输入16进制
    if len(data)%2!=0:
      data="0"+data
    data=bytes.fromhex(data)
    return bytes.fromhex(sm3_hash([i for i in data]))
'''
def birthday_attack():
  start=time.time()
  flag=False
  while (flag==False):
    random1=os.urandom(32)
    random2=os.urandom(32)
    msg1=sm3_gmssl(random1).hex()
    msg2=sm3_gmssl(random2).hex()
    if msg1[0:11]==msg2[0:11]:
      print("完成啦！")
      print("random1 是：",random1)
      print("random2 是：",random2)
      print("msg1 是：",msg1)
      print("msg2 是：",msg2)
      flag=True
  end=time.time()
  print("共花费时间：",end-start)
'''
#(如果您想测试代码的正确性的话，直接运行可能较慢，您可以将[0:11]替换成[0:1]、[0:2]、[0:3]或[0:4]，这样可以较为快速的得出碰撞8bit、16bit、32bit和64bit的结果)
def rho_method():
  start=time.time()
  random1=os.urandom(32)
  msg1=sm3_gmssl(random1)
  msg1_hex=msg1.hex()[0:11]
  msg2=sm3_gmssl_hex(msg1_hex)
  msg2_hex=msg2.hex()[0:11]
  index=1
  while(msg1_hex!=msg2_hex):
    msg1=sm3_gmssl_hex(msg1_hex)
    msg1_hex=msg1.hex()[0:11]
    msg2=sm3_gmssl_hex(sm3_gmssl_hex(msg2_hex[0:11]).hex()[0:11])
    msg2_hex=msg2.hex()[0:11]
    index=index+1
  end=time.time()
  print("完成啦！")
  print("初始的消息为（hex类型）：",random1.hex())
  print("找到的两个碰撞(16进制)为",msg1_hex)
  print("一共走了 ",index," 步")
  print("找到碰撞花费时间为：",end-start)
  #找环口
  msg3=random1
  i=1
  msg3=sm3_gmssl(msg3)
  msg3_hex=msg3.hex()[0:11]
  msg1=sm3_gmssl_hex(msg1_hex)
  msg1_hex=msg1.hex()[0:11]
  while(msg3_hex!=msg1_hex):
    msg3=sm3_gmssl_hex(msg3_hex)
    msg3_hex=msg3.hex()[0:11]
    msg1=sm3_gmssl_hex(msg1_hex)
    msg1_hex=msg1.hex()[0:11]
    i=i+1
    if i>index:
      print('出错！！！！！！')
      break
  print("环口是（hex类型）：",msg3_hex," 是第",i,"个")

  #算环长
  msg4_hex=msg3_hex
  msg1=sm3_gmssl_hex(msg1_hex)
  msg1_hex=msg1.hex()[0:11]
  j=1 
  while(msg4_hex!=msg1_hex):
    msg1=sm3_gmssl_hex(msg1_hex)
    msg1_hex=msg1.hex()[0:11]
    j=j+1

  '''#测试
  test=[]
  msga=sm3_gmssl(random1)
  msga_hex=msga.hex()[0:11]
  test.append(msga_hex)
  for i in range(j+i+5):
    msga=sm3_gmssl_hex(msga_hex)
    msga_hex=msga.hex()[0:11]
    test.append(msga_hex)
  print(test)
  print("环长为：",j)'''
rho_method()