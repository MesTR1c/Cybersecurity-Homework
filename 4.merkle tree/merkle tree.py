import hashlib

def hash_data(data, hash_function = 'sha256'):
    hash_function = getattr(hashlib, hash_function)
    data = data.encode('utf-8')
    return hash_function(data).hexdigest()

def merkle(lst, hash_function = 'sha256'):
    lst1 = []#记录hash值
    for i in lst:
        lst1.append(hash_data("00"+i))                            #xiugai1
    # print(lst1)
    n = len(bin(len(lst)-1)[2:])+1 #merkle树高度
    #print(n)
    lstall=[]
    for i in range(n):
      if i==0:
        lstall.append([])
      else:
        lstall.append([])
    lstall[0]=lst1[0:2**(n-2)] #处理左边的
    #print(lstall)
    k=2**(n-2)
    cengshu=1
    while k>1:
      for j in range(k//2):
        lstall[cengshu].append(hash_data("01"+lstall[cengshu-1][j*2]+lstall[cengshu-1][j*2+1]))                                         #
      k=k//2
      cengshu=cengshu+1
    


    remain=len(lst1)-2**(n-2) # 剩下的数
    remain_length=(remain).bit_length()
    remain_remain=remain-2**(remain_length-1)
    newlist=[]
    if remain_remain>0:
      lstall[n-1-remain_length-1]=lstall[n-1-remain_length-1]+lst1[2**(n-2):2**(n-2)+remain_remain*2]# 补充最下面一层
      cengshu=n-1-remain_length
      newlist=(lst1[2**(n-2):2**(n-2)+remain_remain*2],cengshu-1) #需要补充的
      for j in range(remain_remain):
        lstall[cengshu].append(hash_data("01"+newlist[0][j*2]+newlist[0][j*2+1])) #最下面一层补到上面一层                                     #
    remain1=remain-remain_remain*2 #上面一层还剩下未处理的数
    cengshu=n-1-remain_length
    newlist1=(lst1[2**(n-2)+remain_remain*2:2**(n-2)+remain_remain*2+remain1],cengshu)
    lstall[cengshu]=lstall[cengshu]+lst1[2**(n-2)+remain_remain*2:2**(n-2)+remain_remain*2+remain1] #补齐了全部的叶子。下一步是对右边从最上面叶子节点开始往上推
    k=len(lstall[cengshu])
    while k>1:
      cengshu=cengshu+1
      lstall[cengshu]=[]
      for j in range(k//2):
        lstall[cengshu].append(hash_data("01"+lstall[cengshu-1][j*2]+lstall[cengshu-1][j*2+1]))                                                 #
      k=k//2

    
    for i in range(len(lstall)):
      print("第",i,"层的叶子数为：",len(lstall[i]))
      if i==len(lstall)-1:
        print("root hash为：",lstall[i])
    return lstall,newlist,newlist1

def inclusive(lstall,element,newlist,newlist1):# 传入一个merkle 树的整体结构
  def findbro(num):
    if num%2==0:
      return num+1
    else:
      return num-1
  def check0():
    demand=[]
    cengshu_now=0
    cengshu_all=len(lstall)
    element_temp=element
    for i in range(cengshu_all-1):
      demand.append((cengshu_now,findbro(element_temp)))
      cengshu_now=cengshu_now+1
      element_temp=element_temp//2
    root_hash=lstall[cengshu_all-1][0]
    print("待验证的根hash值为：",root_hash)
    start_hash=lstall[0][element]
    print("准备验证的元素的hash值为：",start_hash)
    result_hash=start_hash
    for i in range(len(demand)):
      cengshu,yuansu=demand[i]
      if yuansu%2==0:
        result_hash=hash_data("01"+lstall[cengshu][yuansu]+result_hash)                                                                              #
      else:
        result_hash=hash_data("01"+result_hash+lstall[cengshu][yuansu])
      #lstall[cengshu][yuansu]
      print("第",i+1,"步，需要的元素（层数，位置）为：",(cengshu,yuansu),"计算结果为：",result_hash)
    if result_hash==root_hash:
      print("元素 ",element," 的存在性证明验证成功!")
      return True
    else:
      print("验证失败")
      return False
  def check1(cengshu_check1):
    demand=[]
    weizhi=lstall[cengshu_check1].index(hash_element)
    cengshu_all=len(lstall)
    cengshu_now=cengshu_check1
    root_hash=lstall[cengshu_all-1][0]
    print("待验证的根hash值为：",root_hash)
    start_hash=hash_element
    print("准备验证的元素的hash值为：",start_hash)
    for i in range(cengshu_all-cengshu_check1-1):
      demand.append((cengshu_now,findbro(weizhi)))
      cengshu_now=cengshu_now+1
      weizhi=weizhi//2
    result_hash=start_hash
    for i in range(len(demand)):
      cengshu,yuansu=demand[i]
      if yuansu%2==0:
        result_hash=hash_data("01"+lstall[cengshu][yuansu]+result_hash)                                                              #
      else:
        result_hash=hash_data("01"+result_hash+lstall[cengshu][yuansu])                                                              #
      #lstall[cengshu][yuansu]
      print("第",i+1,"步，需要的元素（层数，位置）为：",(cengshu,yuansu),"计算结果为：",result_hash)
    if result_hash==root_hash:
      print("元素 ",element," 的存在性证明验证成功!")
      return True
    else:
      print("验证失败")
      return False
  



  n=len(lstall)
  if element<=2**(n-2) or newlist[0]==[]:
    return check0()
  else:
    hash_element=hash_data("00"+str(element))                                                                                      #
    if hash_element in newlist[0]:
      return check1(newlist[1])
    elif hash_element in newlist1[0]:
      return check1(newlist1[1])


def exclusive(lstall,element,l,newlist,newlist1):
  def findsmallest(element):
    small=l[-1]
    for i in range(len(l)):
      if i>element and i<int(small):
        small=str(i)
    return small
  def findbiggest(element):
    big=l[0]
    for i in range(len(l)):
      if i<element and i>int(big):
        big=str(i)
    return big
  for i in l:
    if str(element)==i:
      print("该元素存在于merkle树中")
      return False
  if findsmallest(element)==findbiggest(element):
    print("数据大小超出允许范围，请重试")
    return False
  inclusive_small=inclusive(lstall,int(findsmallest(element)),newlist,newlist1)
  inclusive_big=inclusive(lstall,int(findbiggest(element)),newlist,newlist1)
  condition1=inclusive_small and inclusive_big
  hash_both=hash_data("01"+hash_data("00"+findbiggest(element))+hash_data("00"+findsmallest(element)))                                               #
  condition2=False
  for i in lstall:
    for j in i:
      if j==hash_both:
        condition2=True
        break
  if condition1 and condition2:
    print('')
    print("元素 ",element," 的左右两元素均存在于树中，并且相邻")
    print("元素 ",element," 的非存在性证明验证成功!")
  elif condition1 and not condition2:
    print('')
    print("元素 ",element," 的左右两元素均存在于树中，但不一定相邻")
    print("元素 ",element," 的非存在性证明验证失败!")
l=[]
for i in range(100000):
  l.append(str(i))
lstall,newlist,newlist1=merkle(l)
print("")
print("下面演示存在性证明：")
inclusive(lstall,72322,newlist,newlist1)
print("")
print("下面演示非存在性证明：")
exclusive(lstall,10.5,l,newlist,newlist1)
