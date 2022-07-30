import socket
import random
from random import choice
import sm2
import hashlib
import sm3
HOST = ''
PORT = 9001
ADDR = (HOST, PORT)
BUFFSIZE = 65536
MAX_LISTEN = 5
ENCODING = 'utf-8'
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
def tcpServer():
    global temp
    temp=""
    # TCP服务
    # with socket.socket() as s:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 绑定服务器地址和端口
        s.bind(ADDR)
        # 启动服务监听
        s.listen(MAX_LISTEN)
        print('这里是Alice，等待接入……')
        
        # 等待客户端连接请求,获取connSock
        conn,ad= s.accept()
        #print('远端客户:{} 接入！！！'.format(addr))
        with conn:
          data=conn.recv(BUFFSIZE)
          data=data.decode()
          print("接收到数据为：",data)
          temp=data
        s.close()
random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])
def tcpServer0(data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 绑定服务器地址和端口
        s.bind(ADDR)
        # 启动服务监听
        s.listen(MAX_LISTEN)
        print('这里是Alice，等待接入……')
        # 等待客户端连接请求,获取connSock
        conn,ad= s.accept()
        #print('远端客户:{} 接入！！！'.format(addr))
        with conn:
          conn.send(data.encode(ENCODING))
          print('发送的数据为:',data)
        s.close()
def encrypt(data,pk):
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
def what_Alice_do():
  global temp
  tcpServer()
  p1=temp
  d2=random.randint(1,n-1)
  d2_1=findModReverse(d2,n)
  d2_1p1=sm2_crypt._kg(d2_1,p1)
  pk=sm2_crypt._add_point(d2_1p1,reversepoint(sm2.default_ecc_table["g"]))
  pk=sm2_crypt._convert_jacb_to_nor(pk)
  print("此时可以恢复出公钥为：",pk)
  print("接下来将通过公钥计算出来的密文传给Bob")
  M="Feng Xiangdi"
  M=M.encode()
  C1,C2,C3=encrypt(M,pk)
  tcpServer0(C1)
  tcpServer0(C2)
  tcpServer0(C3)
  tcpServer()
  T1=temp
  T2=sm2_crypt._kg(d2_1,T1)
  tcpServer0(T2)
  klen=int(len(M.hex())/2)
  print(klen)
  tcpServer0(str(klen))
what_Alice_do()