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
        print('this is server! waiting……')
        
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
        print('this is server! waiting……')
        # 等待客户端连接请求,获取connSock
        conn,ad= s.accept()
        #print('远端客户:{} 接入！！！'.format(addr))
        with conn:
          conn.send(data.encode(ENCODING))
          print('发送的数据为:',data)
        s.close()
def hash_to_ecc(msg):#将哈希值映射到椭圆曲线上
  p=int(sm2.default_ecc_table["p"],16)
  n=int(sm2.default_ecc_table["n"],16)
  t=int(msg,16)%p
  for i in range(n):
    x=t+i
    s=(x*x*x)+int(sm2.default_ecc_table["a"],16)*x+int(sm2.default_ecc_table["b"],16)
    if pow(s,(p-1)//2,p)==1:
      y=pow(s,(p+1)//4,p)
      return(x,y)
  return False
def what_server_do():
  #首先建立1w条数据
  lstall=[]
  for i in range(100):
    lstall.append(str(i)+str(i))#简单的明密文对
  lst_h=[]
  for i in range(100):
    lst_h.append(hash_data(lstall[i]))#记录他们的hash值
  ##排序
  def func(str):
    return int(str[:2],16)
  lst_h.sort(key=func)
  lst_group=[]
  #print(len(lst_h[0:100]))
  for i in range(10):
    lst_group.append(lst_h[i*10:(i+1)*10])
  #for i in lst_group:
    #for j in i:
      #j=hash_to_ecc(j)
      #j=hex(j[0])[2:]+hex(j[1])[2:]
  #print(lst_group[44][44])
  #print(len(lst_group))
  #print(len(lst_group[44]))
  tcpServer()#接受k
  k=temp
  tcpServer()#接受v
  v=temp
  hab=sm2_crypt._kg(int(private_key,16),v)
  S=[]
  for i in lst_group:
    for j in i:
      if k==j[:2]:
        S=i
  chuanshu=""
  for i in S:
    i=hash_to_ecc(i)
    i=hex(i[0])[2:]+hex(i[1])[2:]
    i=sm2_crypt._kg(int(private_key,16),i)
    chuanshu=chuanshu+i
    #print(len(chuanshu))
  tcpServer0(hab)
  tcpServer0(chuanshu)
what_server_do()
