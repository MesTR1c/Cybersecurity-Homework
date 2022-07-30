import socket
import random
import sm2
import hashlib
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




Z="Alice Bob"
M="Feng Xiangdi"
M_1=Z+M
e=hash_data(M_1)
k1=random.randint(1,n-1)
q1=sm2_crypt._kg(k1,sm2.default_ecc_table["g"])


k2=random.randint(1,n-1)
q2=sm2_crypt._kg(k2,sm2.default_ecc_table["g"])
k3=random.randint(1,n-1)
k3q1=sm2_crypt._kg(k3,q1)
temp=sm2_crypt._add_point(k3q1,q2)
temp=sm2_crypt._convert_jacb_to_nor(temp)
x1=int(temp[0:64],16)
y1=int(temp[64:128],16)
r=(x1+int(e,16))%n
s2=(d2*k3)%n
s3=(d2*(r+k2))%n

s=((d1*k1)*s2+d1*s3-r)%n

rk=(d1_1*d2_1)%n-1
s_real=(findModReverse((1+rk),n)*(k1*k3+k2-r*rk))%n
print("计算通过分步计算得到的s为:",s)
print("计算通过私钥直接计算的s为:",s_real)
if s==s_real:
  print("算法正确性验证成功！")