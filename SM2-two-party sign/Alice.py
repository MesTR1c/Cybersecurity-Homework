import socket
import random
import sm2
import hashlib
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
  tcpServer()
  q1=temp
  tcpServer()
  e=temp
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
  tcpServer0(str(r))
  tcpServer0(str(s2))
  tcpServer0(str(s3))
what_Alice_do()