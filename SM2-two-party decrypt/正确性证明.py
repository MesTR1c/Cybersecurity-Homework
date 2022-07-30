import random
import sm2
import hashlib
import sm3
from random import choice
HOST = 'localhost'
PORT = 9001
ADDR = (HOST, PORT)
ENCODING = 'utf-8'
BUFFSIZE = 1024
MAX_LISTEN = 5
n=sm2.default_ecc_table["n"]
n=int(n,16)
p=sm2.default_ecc_table["p"]
p=int(p,16)

def gcd(a,b):
    while a!=0:
        a,b = b%a,a
    return b
def findModReverse(a,m):#这个扩展欧几里得算法求模逆
    if gcd(a,m)!=1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m
def hash_data(data, hash_function = 'sha256'):
      hash_function = getattr(hashlib, hash_function)
      data = data.encode('utf-8')
      return hash_function(data).hexdigest()
def reversepoint(point):
  a,b=divmod(int(point[64:128],16),p)
  b=p-b
  point=point[0:64]+hex(b)[2:]
  return point
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'####此处仅为调用类用，无意义
d1=random.randint(1,n-1)
d1_1=findModReverse(d1,n)
sm2_crypt=sm2.CryptSM2(public_key=public_key, private_key=private_key)
p1=sm2_crypt._kg(d1_1,sm2.default_ecc_table["g"])
d2=random.randint(1,n-1)
d2_1=findModReverse(d2,n)
d2_1p1=sm2_crypt._kg(d2_1,p1)
pk=sm2_crypt._add_point(d2_1p1,reversepoint(sm2.default_ecc_table["g"]))
pk=sm2_crypt._convert_jacb_to_nor(pk)
random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])
def encrypt(data):
    # 加密函数，data消息(bytes)
    msg = data.hex() # 消息转化为16进制字符串
    k = random_hex(64)
    C1 = sm2_crypt._kg(int(k,16),sm2.default_ecc_table['g'])
    xy = sm2_crypt._kg(int(k,16),pk)
    x2 = xy[0:64]
    y2 = xy[64:128]
    ml = len(msg)
    t = sm3.sm3_kdf(xy.encode('utf8'), ml/2)
    if int(t,16)==0:
        return None
    else:
        form = '%%0%dx' % ml
        C2 = form % (int(msg, 16) ^ int(t, 16))
        C3 = sm3.sm3_hash([
            i for i in bytes.fromhex('%s%s%s'% (x2,msg,y2))
        ])
        return (C1,C2,C3)

M="Feng Xiangdi"
M=M.encode()
C1,C2,C3=encrypt(M)
#print(len(C2))
#print(C3)
T1=sm2_crypt._kg(d1_1,C1)

T2=sm2_crypt._kg(d2_1,T1)

temp111=sm2_crypt._add_point(T2,reversepoint(C1))
temp111=sm2_crypt._convert_jacb_to_nor(temp111)
klen=len(M.hex())/2
t = sm3.sm3_kdf(temp111.encode('utf8'), klen)
M_1=(int(C2, 16) ^ int(t, 16))
M_1=hex(M_1)[2:]
u=sm3.sm3_hash([i for i in bytes.fromhex('%s%s%s'% (temp111[0:64],M_1,temp111[64:128]))])
print("C3=",C3)
print("u =",u)
if u==C3:
  print("正确性验证成功！")