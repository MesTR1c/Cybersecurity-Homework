import socket
import random
import sm2
import hashlib
import sm3
HOST = 'localhost'
PORT = 9001
ADDR = (HOST, PORT)
ENCODING = 'utf-8'
BUFFSIZE = 65536
MAX_LISTEN = 5
n=sm2.default_ecc_table["n"]
n=int(n,16)
p=sm2.default_ecc_table["p"]
p=int(p,16)
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'####此处仅为调用类用，无意义
sm2_crypt=sm2.CryptSM2(public_key=public_key, private_key=private_key)
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
temp=""
def tcpClient(data):
    # 创建客户套接字
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        # 尝试连接服务器
        s.connect(ADDR)
        print('这里是Bob，连接成功！！')
        s.send(data.encode(ENCODING))
        print('发送的数据为:',data)
        # 关闭客户端套接字
        s.close()
def tcpClient0():
  global temp
  temp=""
  # 创建客户套接字
  with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
      # 尝试连接服务器
      s.connect(ADDR)
      print('这里是Bob，连接成功！！')
      data=s.recv(BUFFSIZE)
      data=data.decode()
      print("接收到数据为：",data)
      temp=data
      # 关闭客户端套接字
      s.close()
def what_Bob_do():
  d1=random.randint(1,n-1)
  d1_1=findModReverse(d1,n)
  p1=sm2_crypt._kg(d1_1,sm2.default_ecc_table["g"])
  tcpClient(p1)
  tcpClient0()
  C1=temp
  tcpClient0()
  C2=temp
  tcpClient0()
  C3=temp
  if int(C1,16)==0:
    print("error")
    return 0
  T1=sm2_crypt._kg(d1_1,C1)
  tcpClient(T1)
  tcpClient0()
  T2=temp
  tcpClient0()
  klen=int(temp)
  temp111=sm2_crypt._add_point(T2,reversepoint(C1))
  temp111=sm2_crypt._convert_jacb_to_nor(temp111)
  #klen=len(M.hex())/2
  t = sm3.sm3_kdf(temp111.encode('utf8'), klen)
  M_1=(int(C2, 16) ^ int(t, 16))
  M_1=hex(M_1)[2:]
  u=sm3.sm3_hash([i for i in bytes.fromhex('%s%s%s'% (temp111[0:64],M_1,temp111[64:128]))])
  print("C3=",C3)
  print("u =",u)
  if u==C3:
    print("恢复的明文为：(16进制)",M_1)
    print("转化为字符串为：",bytes.fromhex(M_1).decode())
what_Bob_do()