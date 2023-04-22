import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKC
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as Signature_PKC

class HandleRSA():
    def create_rsa_key(self,keypath):
        # 伪随机数生成器
        filename = keypath[:-4]
        random_gen = Random.new().read
        # 生成秘钥对实例对象：1024是秘钥的长度
        rsa = RSA.generate(1024, random_gen)
        private_pem = rsa.exportKey()
        with open(filename + ".key", "wb") as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open(filename + ".pub", "wb") as f:
            f.write(public_pem)
        
        if(keypath.endswith(".pub")):
            return public_pem
        elif(keypath.endswith(".key")):
            return private_pem
        else:
            print("Filename is error.")
            return 0

    def encrypt(self, pk, plaintext):
        pk = RSA.import_key(pk)                                 # 加载公钥
        cipher_rsa = Cipher_PKC.new(pk)
        en_data = cipher_rsa.encrypt(plaintext.encode("utf-8")) # 加密 base64 进行编码
        base64_text = base64.b64encode(en_data)
        return base64_text.decode()                             # 返回字符串

    def decrypt(self, sk, en_data):
        base64_data = base64.b64decode(en_data.encode("utf-8")) # base64 解码
        sk = RSA.import_key(sk)
        cipher_rsa = Cipher_PKC.new(sk)
        data = cipher_rsa.decrypt(base64_data,None)
        return data.decode()

    def signature(self,data:str):
        private_key = RSA.import_key(open("datafile/DataOwner.key").read()) # 读取私钥
        # 根据SHA256算法处理签名内容data
        sha_data= SHA256.new(data.encode("utf-8")) # b类型
        # 私钥进行签名
        signer = Signature_PKC.new(private_key)
        sign = signer.sign(sha_data)
        # 将签名后的内容，转换为base64编码
        sign_base64 = base64.b64encode(sign)
        return sign_base64.decode()

    def verify(self,data:str,signature:str) -> bool:
        # 接收到的sign签名 base64解码
        sign_data = base64.b64decode(signature.encode("utf-8"))
        # 加载公钥
        piblic_key = RSA.importKey(open("datafile/DataOwner.pub").read())
        # 根据SHA256算法处理签名之前内容data
        sha_data = SHA256.new(data.encode("utf-8"))  # b类型
        # 验证签名
        signer = Signature_PKC.new(piblic_key)
        is_verify = signer.verify(sha_data, sign_data)

        return is_verify

# if __name__ == '__main__':

#     mrsa = HandleRSA()
#     # mrsa.create_rsa_key()
#     e = mrsa.encrypt('123')
#     d = mrsa.decrypt(e)
#     print(e)
#     print(d)