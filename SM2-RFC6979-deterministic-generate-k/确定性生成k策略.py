import hashlib
import hmac
def hash_data(data, hash_function = 'sha256'):
    hash_function = getattr(hashlib, hash_function)
    data = data.encode('utf-8')
    return hash_function(data).hexdigest()

message="2"
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
n='FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'
h1=hash_data(message)
#print(h1)
V=""
for i in range(32):
  V=V+"01"
#print(V,V.encode())
K=""
for i in range(32):
  K=K+"00"
#print(K,len(K))
K_msg=V+"00"+private_key+h1
K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(K_msg),digestmod=hashlib.sha256).hexdigest()
V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
V_msg=V+"01"+private_key+h1
K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V_msg),digestmod=hashlib.sha256).hexdigest()
V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
flag=False
while(flag==False):
  #print("111")
  T=""
  tlen=0
  qlen=int(n,16).bit_length()
  while(tlen<qlen):
    V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
    T=T+V
    tlen=int(T,16).bit_length()
  k_lower=int(T,16)
  if k_lower>=1 and k_lower<=int(n,16)-1:
    flag=True
  else:
    K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V+"00"),digestmod=hashlib.sha256).hexdigest()
    V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
print("message为：",message)
print("私钥为：",private_key)
print("生成的k为：",k_lower)