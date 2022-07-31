import socket
import random
import sm2
import hashlib
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
private_key= '3a0d75f44b6f06478341e5a7ba895b3bd122602e702f67ca86279221d1c506ab'
public_key= 'ca4e9d3f4ab6827f58f94c9ce566bd32d09f2ebdad7d10c35d3b4450df1135bb1ecf32204ebb935a1d03cc967666c23cd43e854c7c72a6bd59121540a69e3e7f'
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
        print('this is client!success!')
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
      print('this is client!success!')
      data=s.recv(BUFFSIZE)
      data=data.decode()
      print("接收到数据为：",data)
      temp=data
      # 关闭客户端套接字
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
def what_client_do(user,passwd):
  print("准备验证",user,passwd,"是否已泄露")
  h=hash_data(user+passwd)
  k=h[:2]
  h_1=hash_to_ecc(h)
  h_1_str=hex(h_1[0])[2:]+hex(h_1[1])[2:]
  v=sm2_crypt._kg(int(private_key,16),h_1_str)
  #print(len(v))
  tcpClient(k)
  tcpClient(v)
  tcpClient0()
  hab=temp
  tcpClient0()
  chuanshu=temp
  #print(len(chuanshu))
  a_1=findModReverse(int(private_key,16),int(sm2.default_ecc_table["n"],16))
  hb=sm2_crypt._kg(a_1,hab)
  result=[]
  for i in range(10):
    result.append(chuanshu[i*128:(i+1)*128])
  for i in result:
    if i==hb:
      print("用户：密码 已经泄露！！")
      return 0
  print("暂无泄露危险！")
what_client_do("4","4")

