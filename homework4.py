import json
from web3 import Web3, Account, HTTPProvider

# 用于解密
from functools import wraps
from eth_account.messages import encode_defunct

from eth_keys import keys
from eth_utils import decode_hex

# 用于数字加密
import ecies


class ethereumHandler_OP():
    # 类级变量
    myPrivateKey = None
    myPublicAddr = None
    iflogin = None

    """初始化连接以太坊私链"""

    def __init__(self):
        self.web3 = Web3(HTTPProvider("http://localhost:8545"))
        # 检查是否连接成功
        if self.web3.eth.getBlock(0) is None:
            print("Failed to connect!")
        elif self.web3.isConnected():
            print("Successfully connected")

    def PrivateKey_PublicKey_Address(self):
        # 读取keystore文件
        with open(
                r"E:\PycharmProjects\btc\data\keystore\UTC--2021-03-23T07-27-44.500405400Z--a46c666d76e5c044cd8d6b21d3cdf76d5571f48e",
                "r") as f:
            self.encrypted_key = f.read()
        # 可以看到keystore中存储的是json格式的数据
        print("读取到的keystore文件中的信息：", self.encrypted_key)
        # 从keystore中获取私钥privatekey，需要输入密码（注意这里的密码并不是私钥）
        self.privatekey = Account.decrypt(self.encrypted_key, "123")
        print("私钥：", self.privatekey)
        # 先创建keys模块下的私钥对象
        priv_key = keys.PrivateKey(self.privatekey)
        print("priv_key:", priv_key)
        # 再解出公钥
        self.public_key = priv_key.public_key

        print("公钥：", self.public_key)
        # 这里的公钥是64字节,是压缩的
        print("公钥长度：", len(str(self.public_key)))
        # 对公钥使用SHA3加密算法
        sha3_pub_key = Web3.keccak(hexstr=str(self.public_key))
        print("sha3_pub_key", sha3_pub_key)
        # 取后20个字节
        print('从公钥生成地址：', Web3.toHex(sha3_pub_key[-20:]))

    def encryptMsg(self, _msg):
        '''
        params:_msg必须是字节bytes类型，由b''定义的字符串
        '''
        encrypted_msg = ecies.encrypt(self.public_key.to_hex(), bytes(_msg, encoding='utf8'))
        return encrypted_msg

    def decryptMsg(self, _encryptedmsg):
        # private_hex = Web3.toHex(self.privatekey)
        recovered_msg = ecies.decrypt(self.privatekey, _encryptedmsg)
        return recovered_msg

    def signtMsg(self, _msg):
        print("original msg:", _msg)
        # 构造加密前的数据体
        premsg = encode_defunct(text=_msg)
        print("预准备的数据体：", premsg)
        signedmsg = Account.sign_message(premsg, self.privatekey)
        print("签名后的信息：", signedmsg)

    def vertifyMsg(self, _signedmsg):
        print(Account.recover_message("Hello,world!", ))

    def test(self):
        private_1 = '0xa1d0f3ddbbfcc257c06adfb5c0cf96704cb7fdaba620bc8925149c25fd8b8569'
        public_1 = '0xc46d2b24d58ac4f1c8e50246cfbcb32fac785dba1376d13ffb712b022135e513020df7fa655b75197c24687b268d2f14cea382ca9f52ef392ab2e0f1734094da'
        print(len(public_1))
        address_1 = '0xa46c666d76e5c044cd8d6b21d3cdf76d5571f48e'
        encryptmsg = ecies.encrypt(public_1, b'hello,world!')
        print("加密的信息：", encryptmsg)
        decryptmsg = ecies.decrypt(private_1, encryptmsg)
        print("解密的信息：", decryptmsg)


if __name__ == "__main__":
    eth = ethereumHandler_OP()
    eth.PrivateKey_PublicKey_Address()
    # 调用加密解密函数
    encrypted_msg = eth.encryptMsg("Hello,world!11")
    print("加密信息如下：",encrypted_msg)
    print("解密信息:",eth.decryptMsg(encrypted_msg))
