---
layout:     post
title:      Rev知识点
subtitle:   1
date:       2024-4-29
author:     Aaron
header-img: img/home-bg-geek.jpg
catalog: true
tags:
    - Re

---

# Reverse

## 加密算法

### Tea

TEA是Tiny Encryption Algorithm的缩写，以加密解密速度快，实现简单著称。TEA算法每一次可以操作64bit(8byte)，采用128bit(16byte)作为key，算法采用迭代的形式，推荐的迭代轮数是64轮，最少32轮。为解决TEA算法密钥表攻击的问题，TEA算法先后经历了几次改进，从XTEA到BLOCK TEA，直至最新的XXTEA。XTEA也称做TEAN，它使用与TEA相同的简单运算，但四个子密钥采取不正规的方式进行混合以阻止密钥表攻击。Block TEA算法可以对32位的任意整数倍长度的变量块进行加解密的操作，该算法将XTEA轮循函数依次应用于块中的每个字，并且将它附加于被应用字的邻字。XXTEA使用跟Block TEA相似的结构，但在处理块中每个字时利用了相邻字，且用拥有两个输入量的MX函数代替了XTEA轮循函数。上面提到的相邻字其实就是数组中相邻的项。

TEA系列算法中均使用了一个DELTA常数，但DELTA的值对算法并无什么影响，只是为了避免不良的取值，推荐DELTA的值取为黄金分割数(5√-2) / 2与232的乘积，取整后的十六进制值为0x9e3779B9，用于保证每一轮加密都不相同。



```c++
#include<iostream>
#include<algorithm>
#include<cstdio>
#include<cmath>
#include<map>
#include<vector>
#include<queue>
#include<stack>
#include<set>
#include<string>
#include<cstring>
#include<list>
#include<stdlib.h>
using namespace std;

void TEA(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;  // 根据TEA算法，解密轮次的计算需要初始化sum
    uint32_t delta = 0x9e3779b9;
 	
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
 
    v[0] = v0;
    v[1] = v1;
}

void tea_decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i; 
    uint32_t delta = 0x9e3779b9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3) ;
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1) ;
        sum -= delta;

    }
    v[0] = v0;v[1] = v1;

}
int main()
{

    uint32_t key[] = { 0x67626463,0x696D616E,0x79645F65,0x6B696C69 };

    uint32_t data[] = {
      0x31363010,0xAD938623, 0x8492D4C5, 0x7567E366, 0xC786696B, 0xA0092E31, 0xDB695733, 0xDD13A893, 0x88D8A53E, 0x7E845437
    };
    
    //WATCH OUT!!
    for (int i = 0; i < 10; i += 2) {
    tea_decrypt(&data[i], key);
    }
    
    printf("%s", data);

}     
```



**Python版**

```python
from ctypes import *

def encrypt(v, k):
    v0 = c_uint32(v[0])
    v1 = c_uint32(v[1])
    summ = c_uint32(0)
    delta = 0x9e3779b9

    k0, k1, k2, k3 = c_uint32(k[0]), c_uint32(k[1]), c_uint32(k[2]), c_uint32(k[3])
    
    print("%#x %#x" % (v0.value, v1.value))
    print("%#x %#x %#x %#x" % (k0.value, k1.value, k2.value, k3.value))

    w = [0,0]
    for i in range(32):
        summ.value += delta
        v0.value += ((v1.value << 4) + k0.value) ^ (v1.value + summ.value) ^ ((v1.value >> 5) + k1.value)
        v1.value += ((v0.value << 4) + k2.value) ^ (v0.value + summ.value) ^ ((v0.value >> 5) + k3.value)
    w[0], w[1] = v0, v1
    return w

def decrypt(v, k):
    v0 = c_uint32(v[0])
    v1 = c_uint32(v[1])
    summ = c_uint32(0xC6EF3720)
    delta = 0x9e3779b9

    k0, k1, k2, k3 = c_uint32(k[0]), c_uint32(k[1]), c_uint32(k[2]), c_uint32(k[3])
    
    print("%#x %#x" % (v0.value, v1.value))
    print("%#x %#x %#x %#x" % (k0.value, k1.value, k2.value, k3.value))

    w = [0,0]
    for i in range(32):
        v1.value -= ((v0.value << 4) + k2.value) ^ (v0.value + summ.value) ^ ((v0.value >> 5) + k3.value)
        v0.value -= ((v1.value << 4) + k0.value) ^ (v1.value + summ.value) ^ ((v1.value >> 5) + k1.value)
        summ.value -= delta
    w[0], w[1] = v0, v1
    return w


v = [1,2]
k = [1,2,3,4]
ret = encrypt(v,k)
print("%#x %#x" % (ret[0].value, ret[1].value))
enc = [0xf99e87a6, 0xa5b88bf3]
dec = decrypt(enc,k)
print("%#x %#x" % (dec[0].value, dec[1].value))


```

TEA算法是较为基础的算法，在此基础上还有xTEA和xxTEA。

**出题方式**

1. 直接C语言算法
2. 特殊：使用特殊大数计算函数（ADD，SUB，MUL，XOR，ROL，ROR等），模拟SSA风格的计算方式
3. 改变加密轮数或delta的值，变体TEA
4. `delta`的值不直接给，而是先拆成两个数字，然后在异或后得到`delta`，来防止被`FindCrypt`直接检测到

**识别方式**

1. 简单的直接`FindCrypt`直接发现
2. 识别特征值



#### xTea

XTEA是TEA的扩展，也称做TEAN，它使用与TEA相同的简单运算，同样是一个64位块的Feistel密码，使用128位密钥，建议64轮, 但四个子密钥采取不正规的方式进行混合以阻止密钥表攻击



xTEA的加密轮函数为：

```c++
v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[(sum >> 11) & 3]);
v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[sum & 3]);
```



XTEA算法在TEA算法的基础上进行了改进，主要改进有以下几点：

1. 增加了迭代轮数：TEA算法迭代轮数为32轮，XTEA算法增加到了64轮，加强了加密强度。
2. 改进了密钥扩展算法：XTEA算法的密钥扩展算法相对于TEA算法更为复杂和高效。
3. 加入了反向迭代：XTEA算法加入了反向迭代，即加密和解密的过程完全相同。
4. 可变的块大小：XTEA算法的块大小可变，可以是64位、128位等多种长度，提供了更加灵活的加密选项。
5. 增加了数据完整性保护：XTEA算法可以通过增加MAC（Message Authentication Code）来保护数据完整性，防止数据在传输过程中被篡改。

```c++
#include <stdio.h>
#include <stdint.h>

//加密函数
void encrypt(unsigned int num_rounds, uint32_t v[2], uint32_t key[4]){
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9e3779b9;

    for(int i=0; i<num_rounds; i++){
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        //printf("%#x %#x\n",v0,v1);
    }
    v[0] = v0;
    v[1] = v1;
}

//解密函数
void decrypt(unsigned int num_rounds, uint32_t v[2], uint32_t key[4]){
    uint32_t v0=v[0], v1=v[1], delta=0x9e3779b9, sum=delta*num_rounds;
    for(int i=0; i<num_rounds; i++){
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}


int main(void){
    uint32_t v[2]={1,2};
    uint32_t k[4]={1,2,3,4};
    unsigned int r=32;//加密轮数建议取值为32
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("%#x %#x\n",v[0],v[1]);
    encrypt(r, v, k);
    printf("%#x %#x\n",v[0],v[1]);
    decrypt(r, v, k);
    printf("%#x %#x\n",v[0],v[1]);
    return 0;
}
```



**Python版**

```python
import sys
import os
from ctypes import *

def encrypt(num_rounds, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    summ = c_uint32(0)
    delta = 0x9e3779b9

    #print("%#10x %#10x" % (v0.value, v1.value))
    #print("%#10x" % (summ.value))

    for i in range(num_rounds):
        v0.value += (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (summ.value + key[summ.value & 3])
        summ.value += delta
        v1.value += (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (summ.value + key[(summ.value>>11) & 3])
        #print("%#10x %#10x" % (v0.value, v1.value))
    w = [v0.value, v1.value]
    return w

def decrypt(num_rounds, v, key):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9e3779b9
    summ = c_uint32(delta*num_rounds)

    print("%#10x %#10x" % (v0.value, v1.value))

    for i in range(num_rounds):
        v1.value -= (((v0.value << 4) ^ (v0.value >> 5)) + v0.value) ^ (summ.value + key[(summ.value>>11)&3])
        summ.value -= delta
        v0.value -= (((v1.value << 4) ^ (v1.value >> 5)) + v1.value) ^ (summ.value + key[summ.value & 3])

    w = [v0.value, v1.value]
    return w

v = [1,2]
k = [1,2,3,4]

ret = encrypt(32,v,k)
print("%#x %#x" % (ret[0], ret[1]))
enc = [0xf4420bdd, 0xd58bca18]
dec = decrypt(32,enc,k)
print("%#x %#x" % (dec[0], dec[1]))
```



#### xxTea

XXTEA是一个非平衡Feistel网络分组密码，在可变长度块上运行，这些块是32位大小的任意倍数（最小64位），使用128位密钥, 是目前TEA系列中最安全的算法，但性能较上两种有所降低。

```c++
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
 
void btea(uint32_t *v, int n, uint32_t const key[4]){
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    /* Coding Part */
    if (n > 1) {
        rounds = 6 + 52/n;
        sum = 0;
        z = v[n-1];
        do{
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++){
                y = v[p+1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1)/* Decoding Part */{
        n = -n;
        rounds = 6 + 52/n;
        sum = rounds*DELTA;
        y = v[0];
        do{
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--){
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}
 
int main()
{
    uint32_t v[2]= {1,2};
    uint32_t const k[4]= {2,2,3,4};
    int n= 2; //n的绝对值表示v的长度，取正表示加密，取负表示解密
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    
    /*方法1*/
    printf("%#10x %#10x\n",v[0],v[1]);
    btea(v, n, k);
    printf("%#10x %#10x\n",v[0],v[1]);
    btea(v, -n, k);
    printf("%#10x %#10x\n",v[0],v[1]);
    
    /*方法2*/
    int n1=abs(n);
    for (int i = 0; i < n1; i++)
    {
        //printf("0x%x ",v[i]);
		printf("%c%c%c%c",*((unsigned char*)&v[i] + 0) & 0xff ,*((unsigned char*)&v[i] + 1) & 0xff, *((unsigned char*)&v[i] + 2) & 0xff, *((unsigned char*)&v[i] + 3)&0xff);
    }
    
    return 0;
}

```



**Python版**

可以直接pip安装模块

```
pip install xxtea-py
```

*使用*-->

python2

```python
import xxtea
text = "Hello World! 你好，中国！"
key = "1234567890"
encrypt_data = xxtea.encrypt(text, key)
decrypt_data = xxtea.decrypt(encrypt_data, key)
print(text == decrypt_data);
```

python3

```python
import xxtea
text = "Hello World! 你好，中国！"
key = "1234567890"
encrypt_data = xxtea.encrypt(text, key)
decrypt_data = xxtea.decrypt_utf8(encrypt_data, key)
print(text == decrypt_data);
```

直接使用模块分析的话如果魔改了逻辑或者delta值被修改那么就不能用了，还是推荐使用cpp脚本修改方便



### RC4

RC4是一种流密码算法，由Ron Rivest于1987年设计。RC4的名字源于它是“Rivest Cipher 4”的缩写。

RC4算法使用变量长度的密钥来生成伪随机比特流，该比特流可以与明文进行异或运算得到密文。RC4算法的特点是简单高效，适用于低带宽的网络通信。

RC4算法的核心是密钥调度算法（Key Scheduling Algorithm，KSA）和伪随机生成算法（Pseudo-Random Generation Algorithm，PRGA）。密钥调度算法将密钥按字节分成256个元素的S盒，然后对S盒进行混淆和置换，生成256个随机排列的字节，即密钥调度表。伪随机生成算法则使用密钥调度表和一个计数器来生成伪随机比特流。

RC4算法的加密过程如下：

1. 初始化：创建一个256字节的S盒，使用密钥调度算法生成密钥调度表，并初始化计数器。
2. 生成伪随机比特流：使用密钥调度表和计数器生成伪随机比特流。
3. 明文加密：将明文与伪随机比特流进行异或运算得到密文。
4. 重复步骤2和3：使用相同的密钥和初始化向量对每个数据块重复执行步骤2和3。

RC4算法的  *解密过程与加密过程*  相同，因为异或运算是可逆的。

需要注意的是，RC4算法的密钥长度不应太短，否则容易受到攻击。通常建议使用长度为128位或以上的密钥。此外，RC4算法在初始化时需要避免使用相同的密钥和初始化向量，否则会导致生成的伪随机比特流重复，从而降低加密强度。



**加密步骤**：

1.初始化s盒与t盒

```cpp
 int Len = strlen(key);
 for(i=0;i<256;i++) {
        s[i]=i;
        T[i]=key[i%Len];
    }
```

2.初始化排列s盒

```cpp
 for(i=0;i<256;i++) {
        j=(j+s[i]+k[i])%256;
        tmp=s[i];
        s[i]=s[j];//交换s[i]和s[j]
        s[j]=tmp;
    }
```

3.产生密钥流

```cpp
int i=0,j=0,t=0;
unsigned long k=0;
unsigned char tmp;
for(k=0;k < len;k++)
{
    i=(i+1)%256;
    j=(j+s[i])%256;
    tmp=s[i];
    s[i]=s[j]; //交换s[x]和s[y]
    s[j]=tmp;
}
```



***完整加密解密函数***

```cpp
#include<stdio.h>
#include<string.h>
typedef unsigned longULONG;
 
/*初始化函数*/
void rc4_init(unsigned char*s, unsigned char*key, unsigned long Len)
{
    int i = 0, j = 0;
    char k[256] = { 0 };
    unsigned char tmp = 0;
    for (i = 0; i<256; i++)
    {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i = 0; i<256; i++)
    {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];//交换s[i]和s[j]
        s[j] = tmp;
    }
}
 
/*加解密*/
void rc4_crypt(unsigned char*s, unsigned char*Data, unsigned long Len)
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for (k = 0; k<Len; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];//交换s[x]和s[y]
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] ^= s[t];
    }
}
 
int main()
{
    unsigned char s[256] = { 0 }, s2[256] = { 0 };//S-box
    char key[256] = { "justfortest" };
    char pData[512] = "这是一个用来加密的数据Data";
    unsigned long len = strlen(pData);
    int i;
 
    printf("pData=%s\n", pData);
    printf("key=%s,length=%d\n\n", key, strlen(key));
    rc4_init(s, (unsigned char*)key, strlen(key));//已经完成了初始化
    printf("完成对S[i]的初始化，如下：\n\n");
    for (i = 0; i<256; i++)
    {
        printf("%02X", s[i]);
        if (i && (i + 1) % 16 == 0)putchar('\n');
    }
    printf("\n\n");
    for (i = 0; i<256; i++)//用s2[i]暂时保留经过初始化的s[i]，很重要的！！！
    {
        s2[i] = s[i];
    }
    printf("已经初始化，现在加密:\n\n");
    rc4_crypt(s, (unsigned char*)pData, len);//加密
    printf("pData=%s\n\n", pData);
    printf("已经加密，现在解密:\n\n");
    //rc4_init(s,(unsignedchar*)key,strlen(key));//初始化密钥
    rc4_crypt(s2, (unsigned char*)pData, len);//解密
    printf("pData=%s\n\n", pData);
    return 0;
}
```

### BASE

*Base64原理*
用一句话来说明Base64编码的原理：“把3个字节变成4个字节”。

这么说吧，3个字节一共24个bit，把这24个bit依次分成4个组，每个组6个bit，再把这6个bit塞到一个字节中去(最高位补两个0就变成8个bit)，就会变成4个字节。没了。

因为6个bit最多能表示2^6=64，也就是说Base64编码出来的字符种类只有64个，这也是Base64名字的由来。

那我们就要从ASCII中0x20 ~ 0x7E是可打印字符选出64个普通的ASCII字符

#### 换表

```python
import base64
import string
 
str1 = "AMHo7dLxUEabf6Z3PdWr6cOy75i4fdfeUzL17kaV7rG=" #待解秘字符串
 
string1 = "qaCpwYM2tO/RP0XeSZv8kLd6nfA7UHJ1No4gF5zr3VsBQbl9juhEGymc+WTxIiDK" #新表
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
 
print (base64.b64decode(str1.translate(str.maketrans(string1,string2))))
```



### Rot

rot密码其实可以看作是凯撒密码的一种变式

本质都是移位运算

rot密码按种类大致分为以下几类

rot5：只将字符串中的数字进行加密，步数为5，同时在0-9十个数字进行循环，如1在rot5加密后为6，而6在rot5加密后为1

------

rot13：只将字符串中的字母进行加密，步数为13，加密方式上最接近凯撒密码，分别在A-Z或a-z之间循环，如A在rot13加密后为N,Z在rot13加密后为M

------

rot18:字面意思(5+13=18) 即将上述两种加密方式结合，分别对数字和字母进行相应的操作

------

rot47:由于无论是rot5、rot13或rot18都只能对数字和字母进行相应的加密，而对“！@#￥%&”之类的符号却缺少加密，因此在此基础上引入ASCII码

如果理解了上面的rot5、rot13、rot18，那么rot47也相当好理解了，只是将步数改为47而已（同样存在循环）

对数字、字母、常用符号进行编码，按照它们的ASCII值进行位置替换，用当前字符ASCII值往前数的第47位对应字符替换当前字符，例如当前为小写字母z，编码后变成大写字母K，当前为数字0，编码后变成符号_。

***注意：用于ROT47编码的字符其ASCII值范围是33－126（原因是由于0-32以及127与字符表示无关！！）***

#### Rot5

```python
def rot5_encrypt(plaintext):
    ciphertext = ""
    for c in plaintext:
        if c.isdigit():
            new_digit = (int(c) + 5) % 10
            ciphertext += str(new_digit)
        else:
            ciphertext += c
    return ciphertext

def rot5_decrypt(ciphertext):
    plaintext = ""
    for c in ciphertext:
        if c.isdigit():
            new_digit = (int(c) - 5) % 10
            plaintext += str(new_digit)
        else:
            plaintext += c
    return plaintext


```



#### Rot13

```python
def rot13_encrypt(plaintext: str) -> str:
    ciphertext = ""
    for c in plaintext:
        if c.isalpha():
            if c.isupper():
                new_ascii = (ord(c) - 65 + 13) % 26 + 65
            else:
                new_ascii = (ord(c) - 97 + 13) % 26 + 97
            ciphertext += chr(new_ascii)
        else:
            ciphertext += c
    return ciphertext


def rot13_decrypt(ciphertext: str) -> str:
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            if c.isupper():
                new_ascii = (ord(c) - 65 - 13) % 26 + 65
            else:
                new_ascii = (ord(c) - 97 - 13) % 26 + 97
            plaintext += chr(new_ascii)
        else:
            plaintext += c
    return plaintext

```



#### Rot18

```python
def rot18_encrypt(plaintext: str) -> str:
    ciphertext = ""
    for c in plaintext:
        if c.isalpha():
            if c.isupper():
                new_ascii = (ord(c) - 65 + 18) % 26 + 65
            else:
                new_ascii = (ord(c) - 97 + 18) % 26 + 97
            ciphertext += chr(new_ascii)
        else:
            ciphertext += c
    return rot5_encrypt(rot13_encrypt(plaintext))


def rot18_decrypt(ciphertext: str) -> str:
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            if c.isupper():
                new_ascii = (ord(c) - 65 - 18) % 26 + 65
            else:
                new_ascii = (ord(c) - 97 - 18) % 26 + 97
            plaintext += chr(new_ascii)
        else:
            plaintext += c
    return rot5_decrypt(rot13_decrypt(ciphertext))

```



#### Rot47

```py
# rot-47 解密
s = "nihao"
x = []
for i in range(len(s)):
    j = ord(s[i])  # 字符在ASCII中的序号
    if j >= 33 and j <= 126:  # 用于ROT47编码的字符其ASCII值范围是33－126
        x.append(chr(33 + ((j + 14) % 94)))
    else:
        x.append(s[i])
 
a = "".join(x)
print(a)
```



### Z3  Solve

*Z3* 是一个微软出品的开源约束求解器，能够解决很多种情况下的给定部分约束条件寻求一组满足条件的解的问题 功能强大且易于使用。



这个Z3可以用pip直接安装

```
pip install z3-solver
```

z3中有3种类型的变量，分别是整型(Int)，实型(Real)和向量(BitVec)。

对于整数类型数据，基本API：

1. **Int(name, ctx=None)，创建一个整数变量，name是名字**
2. **Ints (names, ctx=None)，创建多个整数变量，names是空格分隔名字**
3. **IntVal (val, ctx=None)，创建一个整数常量，有初始值，没名字。**

对于实数类型的API与整数类型一致，向量(BitVec)则稍有区别：

1. **Bitvec(name,bv,ctx=None)，创建一个位向量，name是他的名字，bv表示大小**
2. **BitVecs(name,bv,ctx=None)，创建一个有多变量的位向量，name是名字，bv表示大小**
3. **BitVecVal(val,bv,ctx=None)，创建一个位向量，有初始值，没名字。**

**simplify(表达式)，对可以简化的表达式进行简化。**



完整的API使用可以参考：[完整API文档可参考：https://z3prover.github.io/api/html/namespacez3py.html]()

#### 求解

##### 二元一次方程

比如使用z3解二元一次方程：

$x-y = 3$

$3x-8y=4$

solve直接求解：

```python
from z3 import *

x, y = Reals('x y')
solve(x-y == 3, 3*x-8*y == 4)

#[y = 1, x = 4]
```



如果需要取出指定变量的结果，可以使用Solver求解器：

1. s=solver()，创建一个解的对象。
2. s.add(条件)，为解增加一个限制条件
3. s.check()，检查解是否存在，如果存在，会返回"sat"
4. modul()，输出解得结果

```python
x, y = Reals('x y')
solver = Solver()
qs = [x-y == 3, 3*x-8*y == 4]
for q in qs:
    solver.add(q)
if solver.check() == sat:
    result = solver.model()
print(result)
print("x =", result[x], ", y =", result[y])

#[y = 1, x = 4]
#x = 4 , y = 1
```



**⚠️注意：没有push过的约束条件时直接pop会导致报出`Z3Exception: b'index out of bounds'`错误。**



##### 线性多项式约束

约束条件为：

   x>2y<10x+2*y=7

上述约束x和y都是整数，我们需要找到其中一个可行解：

```python
x, y = Ints('x y')
solve([x > 2, y < 10, x + 2*y == 7])
```

结果：

```
[y = 0, x = 7]
```

当然，实际可行的解不止这一个，z3只能找到其中一个可行的解。

##### 非线性多项式约束

约束条件为：

$ x^2 + y^2 > 3 $

$ x^3 + y < 5 $

上述约束x和y都是实数，我们需要找到其中一个可行解：

```python
x, y = Reals('x y')
solve(x**2 + y**2 > 3, x**3 + y < 5)
```

结果：

```
[y = 2, x = 1/8]
```

很快就计算出了一个可行解。

### ChaCha20

Chacha20流密码经常和Poly1305消息认证码结合使用，被称为ChaCha20-Poly1305,由Google公司率先在Andriod移动平台中的Chrome中代替RC4使用

ChaCha20加密的初始状态包括了包括了

1、一个128位常量(Constant)

常量的内容为  **0x61707865,0x3320646e,0x79622d32,0x6b206574**

2、一个256位密钥(Key)

3、一个64位计数(Counter)

4、一个64位随机数(Nonce)

一共64字节其排列成4 * 4的32位字矩阵如下所示：（实际运算为小端

![image-20240429003513302](assets/image-20240429003513302.png)

##### 1/4轮操作

在ChaCha20算法当中, 一个基础的操作即为1/4轮运算, 它主要操作4个32位的无符号整数，具体操作如下:

```
a += b; d ^= a; d <<<= 16;
c += d; b ^= c; b <<<= 12;
a += b; d ^= a; d <<<= 8;
c += d; b ^= c; b <<<= 7;
```



##### 块函数

(ChaCha20 Block Function)

这个块函数输入是之前所生成的状态矩阵, 最终输出64bit的"随机化"的字节, 具体操作如下所示:

```c
static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) { // num_rounds 一般为20 
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {
        //odd round  // 奇数行变换
        chacha20_quarterround(x, 0, 4,  8, 12);
        chacha20_quarterround(x, 1, 5,  9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        //even round    // 偶数列变换
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7,  8, 13);
        chacha20_quarterround(x, 3, 4,  9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

```

到这里, ChaCha20的基本原理就结束了, 整个密码结构并不是很复杂, 整体思路也比较清晰。

##### ChaCha20代码实现



**Rust版本：**

```rust
// https://datatracker.ietf.org/doc/html/rfc8439
pub struct ChaCha20 {
    state: [u32; 16],
}
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}
impl ChaCha20 {
    pub fn new(key: [u32; 8], counter: u32, nonce: [u32; 3]) -> ChaCha20 {
        return ChaCha20 {
            state: [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                key[0], key[1], key[2], key[3],
                key[4], key[5], key[6], key[7],
                counter, nonce[0], nonce[1], nonce[2],
            ]
        };
    }
    fn chacha20_block(&mut self) -> Vec<u8> {
        let mut key_stream = vec![];
        let mut initial_state = self.state;
        for _ in 1..=10 {
            quarter_round(&mut initial_state, 0, 4, 8, 12);
            quarter_round(&mut initial_state, 1, 5, 9, 13);
            quarter_round(&mut initial_state, 2, 6, 10, 14);
            quarter_round(&mut initial_state, 3, 7, 11, 15);
            quarter_round(&mut initial_state, 0, 5, 10, 15);
            quarter_round(&mut initial_state, 1, 6, 11, 12);
            quarter_round(&mut initial_state, 2, 7, 8, 13);
            quarter_round(&mut initial_state, 3, 4, 9, 14);
        }
        for (index, value) in initial_state.iter().enumerate() {
            let new_value = self.state[index].wrapping_add(*value);
            for &x in new_value.to_le_bytes().iter() {
                key_stream.push(x);
            }
        }
        key_stream
    }
    pub fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
        let mut result = vec![];
        for chunk in message.chunks(64) {
            for (&key, value) in chunk.iter().zip(self.chacha20_block()) {
                result.push(key ^ value);
            }
            self.state[12] += 1;
        }
        return result;
    }
}
#[cfg(test)]
mod test {
    use crate::chacha20::ChaCha20;
    #[test]
    fn test() {
        let key = [0u32; 8];
        let nonce = [0x0u32; 3];
        let mut cc20 = ChaCha20::new(key, 1, nonce);
        let result = cc20.encrypt("1234".as_bytes());
        println!("{:?}", result);
    }
}
```



**C语言：**

```c++
#include <stdint.h>
#include <string.h>
#include "chacha20.h"

static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}

static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) { // num_rounds 一般为20 
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {    
        //odd round
        chacha20_quarterround(x, 0, 4,  8, 12);
        chacha20_quarterround(x, 1, 5,  9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        //even round 
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7,  8, 13);
        chacha20_quarterround(x, 3, 4,  9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++) {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    for (i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}
```

**chacha20.h**

```
#ifndef __CHACHA20_H
#define __CHACHA20_H
#include <stdint.h>

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *input, uint8_t *output, int inputlen);

#endif
```

**main.cpp**

```c++
#include <stdio.h>
#include "chacha20.h"

int main(int argc, char **argv) {
    int i;

    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };

    uint8_t nonce[] = {                // 随机数 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t input[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    uint8_t encrypt[114];
    uint8_t decrypt[114];

    ChaCha20XOR(key, 1, nonce, input, encrypt, 114);                //1 就是conter 
    ChaCha20XOR(key, 1, nonce, encrypt, decrypt, 114);

    printf("\nkey:");
    for (i = 0; i < 32; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", key[i]);
    }

    printf("\n\nnonce:\n");
    for (i = 0; i < 12; i++) {
        printf("%02x ", nonce[i]);
    }

    printf("\n\nplaintext:");
    for (i = 0; i < 114; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", input[i]);
    }

    printf("\n\nencrypted:");
    for (i = 0; i < 114; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", encrypt[i]);
    }

    printf("\n\ndecrypted:");
    for (i = 0; i < 114; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", decrypt[i]);
    }

    printf("\n");
    return 0;
}
```



**Python版：**

```python
def main():
    runtests()

def chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)

def chacha20_encrypt(key, counter, nonce, plaintext):
    byte_length = len(plaintext)
    full_blocks = byte_length//64
    remainder_bytes = byte_length % 64
    encrypted_message = b''

    for i in range(full_blocks):
        key_stream = serialize(chacha20_block(key, counter + i, nonce))
        plaintext_block = plaintext[i*64:i*64+64]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(64)]
        encrypted_message += bytes(encrypted_block)
    if remainder_bytes != 0:
        key_stream = serialize(chacha20_block(key, counter + full_blocks, nonce))
        plaintext_block = plaintext[full_blocks*64:byte_length]
        encrypted_block = [plaintext_block[j] ^ key_stream[j] for j in range(remainder_bytes)]
        encrypted_message += bytes(encrypted_block)

    return encrypted_message

# returns a list of 16 32-bit unsigned integers
def chacha20_block(key, counter, nonce):
    BLOCK_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    init_state = BLOCK_CONSTANTS + key + [counter] + nonce
    current_state = init_state[:]
    for i in range(10):
        inner_block(current_state)
    for i in range(16):
        current_state[i] = add_32(current_state[i], init_state[i])

    return current_state

def inner_block(state):
    # columns
    quarterround(state, 0, 4, 8, 12)
    quarterround(state, 1, 5, 9, 13)
    quarterround(state, 2, 6, 10, 14)
    quarterround(state, 3, 7, 11, 15)
    # diagonals
    quarterround(state, 0, 5, 10, 15)
    quarterround(state, 1, 6, 11, 12)
    quarterround(state, 2, 7, 8, 13)
    quarterround(state, 3, 4, 9, 14)

def xor_32(x, y):
    return (x ^ y) & 0xffffffff

def add_32(x, y):
    return (x + y) & 0xffffffff

def rot_l32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def quarterround(state, i1, i2, i3, i4):
    a = state[i1]
    b = state[i2]
    c = state[i3]
    d = state[i4]

    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 16)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 12)
    a = add_32(a, b); d = xor_32(d, a); d = rot_l32(d, 8)
    c = add_32(c, d); b = xor_32(b, c); b = rot_l32(b, 7)

    state[i1] = a
    state[i2] = b
    state[i3] = c
    state[i4] = d

def serialize(block):
    return b''.join([(word).to_bytes(4, 'little') for word in block])

# Test Vectors from RFC 8439
def runtests():

    key = [0x2519EB0A, 0x909CE82E, 0xD6C085EC, 0x545ACF07, 0x24124049, 0x1E1353E7, 0x14AD4F2F, 0xE98FF6DE] 
    plaintext = b"\x8e\x91\x9e\xbe\x6a\x6c\x64\xc1\x02\x02\xf8\xda\xc4\xc8\xd6\x14\xa0\xa3\x9c\x0e\x62\x64\x70\x6d\x02\x02\x0c\x9d\xd2\xd6\xc6\xa8"
    nonce = [0x7369C667, 0xEC4AFF51, 0xABBACD29]
    init_counter = 0x00000001
    ciphertext = chacha20_encrypt(key, init_counter, nonce, plaintext)
    for i in range(len(ciphertext)):
        print(hex(ciphertext[i])[2:],end = " ")
    assert(chacha20_decrypt(key, init_counter, nonce, ciphertext) == plaintext)

    print("All tests passed!")

main();
```



### SMC



#### 自解密



## PC逆向

### Angr

angr 是一个基于符号执行和模拟执行的二进制框架，可以用于二进制的自动分析中

#### 使用 angr 的大概步骤

- 创建 project
- 设置 state
- 新建 符号量 : BVS (bitvector symbolic ) 或 BVV (bitvector value)
- 把符号量设置到内存或者其他地方
- 设置 Simulation Managers ， 进行路径探索的对象
- 运行，探索满足路径需要的值
- 约束求解，获取执行结果

例如：

```python
import angr
project = angr.Project('path_to_binary', auto_load_libs=False)
state = project.factory.entry_state()
sim = project.factory.simgr(state)
sim.explore(find=target)
if simulation.found:
    res = simulation.found[0]
    res = res.posix.dumps(0)
    print("[+] Success! Solution is: {}".format(res.decode("utf-8")))
```

这是一个比较惯例的脚本，适合普通的程序分析与运行，但是我们现在需要对angr中的各个项目的功能进行具体分析



##### **Project 模块**

```python
project = angr.Project(path_to_binary, auto_load_libs=False)
```

对于一个使用 angr.Project 加载的二进制程序，angr 会读取它的一些基本属性：

```text
>>> project=angr.Project("02_angr_find_condition",auto_load_libs=False) 
>>> project.filename 
'02_angr_find_condition'
>>> project.arch 
<Arch X86 (LE)>
>>> hex(project.entry) 
'0x8040464'
```



这些信息会由 angr 自动分析，但是如果你有需要，可以通过 angr.Project 中的其他参数手动进行设定。



##### Loader 模块

而对于一个 Project 对象，它拥有一个自己的 Loader ，提供如下信息：

```text
>>> project.loader 
<Loaded 02_angr_find_condition, maps [0x8048000:0x8407fff]>
>>> project.loader.main_object 
<ELF Object 02_angr_find_condition, maps [0x8048000:0x804f03f]>
>>> project.loader.all_objects 
[<ELF Object 02_angr_find_condition, maps [0x8048000:0x804f03f]>, <ExternObject Object cle##externs, maps [0x8100000:0x8100018]>, <ExternObject Object cle##externs, maps [0x8200000:0x8207fff]>, <ELFTLSObjectV2 Object cle##tls, maps [0x8300000:0x8314807]>, <KernelObject Object cle##kernel, maps [0x8400000:0x8407fff]>]
```

当然实际的属性不止这些，而且在常规的使用中似乎也用不到这些信息，不过这里为了完整性就一起记录一下吧。

Loader 模块主要是负责记录二进制程序的一些基本信息，包括段、符号、链接等。

```text
>>> obj=project.loader.main_object
>>> obj.plt 
{'strcmp': 134513616, 'printf': 134513632, '__stack_chk_fail': 134513648, 'puts': 134513664, 'exit': 134513680, '__libc_start_main': 134513696, '__isoc99_scanf': 134513 
712, '__gmon_start__': 134513728}
>>> obj.sections 

<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>, <.interp | offset 0x154, vaddr 0x8048154, size 0x13>, <.note.ABI-tag | offset 0x168, vaddr 0x8048168, size 0x20> 
, <.note.gnu.build-id | offset 0x188, vaddr 0x8048188, size 0x24>, <.gnu.hash | offset 0x1ac, vaddr 0x80481ac, size 0x20>, <.dynsym | offset 0x1cc, vaddr 0x80481cc, siz 
e 0xa0>, <.dynstr | offset 0x26c, vaddr 0x804826c, size 0x91>, <.gnu.version | offset 0x2fe, vaddr 0x80482fe, size 0x14>, <.gnu.version_r | offset 0x314, vaddr 0x804831 
4, size 0x40>, <.rel.dyn | offset 0x354, vaddr 0x8048354, size 0x8>, <.rel.plt | offset 0x35c, vaddr 0x804835c, size 0x38>, <.init | offset 0x394, vaddr 0x8048394, size 
0x23>, <.plt | offset 0x3c0, vaddr 0x80483c0, size 0x80>, <.plt.got | offset 0x440, vaddr 0x8048440, size 0x8>, <.text | offset 0x450, vaddr 0x8048450, size 0x4ea2>, < 
.fini | offset 0x52f4, vaddr 0x804d2f4, size 0x14>, <.rodata | offset 0x5308, vaddr 0x804d308, size 0x39>, <.eh_frame_hdr | offset 0x5344, vaddr 0x804d344, size 0x3c>, 
<.eh_frame | offset 0x5380, vaddr 0x804d380, size 0x110>, <.init_array | offset 0x5f08, vaddr 0x804ef08, size 0x4>, <.fini_array | offset 0x5f0c, vaddr 0x804ef0c, size 
0x4>, <.jcr | offset 0x5f10, vaddr 0x804ef10, size 0x4>, <.dynamic | offset 0x5f14, vaddr 0x804ef14, size 0xe8>, <.got | offset 0x5ffc, vaddr 0x804effc, size 0x4>, <.go 
t.plt | offset 0x6000, vaddr 0x804f000, size 0x28>, <.data | offset 0x6028, vaddr 0x804f028, size 0x15>, <.bss | offset 0x603d, vaddr 0x804f03d, size 0x3>, <.comment | 
offset 0x603d, vaddr 0x0, size 0x34>, <.shstrtab | offset 0x67fa, vaddr 0x0, size 0x10a>, <.symtab | offset 0x6074, vaddr 0x0, size 0x4d0>, <.strtab | offset 0x6544, va 
ddr 0x0, size 0x2b6>]>
```



对外部库的链接也同样支持查找：

```text
>>> project.loader.find_symbol('strcmp')     
<Symbol "strcmp" in cle##externs at 0x8100000>
>>> project.loader.find_symbol('strcmp').rebased_addr 
135266304 
>>> project.loader.find_symbol('strcmp').linked_addr 
0 
>>> project.loader.find_symbol('strcmp').relative_addr 
0
```



同时也支持一些加载选项：

- auto_load_libs：是否自动加载程序的依赖
- skip_libs：避免加载的库
- except_missing_libs：无法解析共享库时是否抛出异常
- force_load_libs：强制加载的库
- ld_path：共享库的优先搜索搜寻路径



我们知道，在一般情况下，加载程序都会将 auto_load_libs 置为 False ，这是因为如果将外部库一并加载，那么 Angr 就也会跟着一起去分析那些库了，这对性能的消耗是比较大的。



而对于一些比较常规的函数，比如说 malloc 、printf、strcpy 等，Angr 内置了一些替代函数去 hook 这些系统库函数，因此即便不去加载 libc.so.6 ，也能保证分析的正确性。这部分内容接下来会另说。



##### factory 模块

该模块主要负责将 Project 实例化。

我们知道，加载一个二进制程序只是符号执行能够开始的第一步，为了实现符号执行，我们还需要为这个二进制程序去构建符号、执行流等操作。这些操作会由 Angr 帮我们完成，而它也提供一些方法能够让我们获取到它构造的一些细节。



##### Block 模块

Angr 对程序进行抽象的一个关键步骤就是从二进制机器码去重构 CFG ，而 Block 模块提供了和它抽象出的基本块间的交互接口：

```text
>>> project.factory.block(project.entry) 
<Block for 0x8048450, 33 bytes> 
>>> project.factory.block(project.entry).pp() 
        _start: 
8048450  xor     ebp, ebp 
8048452  pop     esi 
8048453  mov     ecx, esp 
8048455  and     esp, 0xfffffff0 
8048458  push    eax 
8048459  push    esp 
804845a  push    edx 
804845b  push    __libc_csu_fini 
8048460  push    __libc_csu_init 
8048465  push    ecx 
8048466  push    esi 
8048467  push    main 
804846c  call    __libc_start_main
>>> project.factory.block(project.entry).instruction_addrs 
(134513744, 134513746, 134513747, 134513749, 134513752, 134513753, 134513754, 134513755, 134513760, 134513765, 134513766, 134513767, 134513772)
```



可以看出 Angr 用 call 指令作为一个基本块的结尾。在 Angr 中，它所识别的基本块和 IDA 里看见的 CFG 有些许不同，它会把所有的跳转都尽可能的当作一个基本块的结尾。

> 当然也有无法识别的情况，比如说使用寄存器进行跳转，而寄存器的值是上下文有关的，它有可能是函数开始时传入的一个回调函数，而参数有可能有很多种，因此并不是总能够识别出结果的。

```text
>>> block. 
block.BLOCK_MAX_SIZE           block.capstone                 block.instructions             block.reset_initial_regs()     block.size 
block.addr                     block.codenode                 block.parse(                   block.serialize()              block.thumb 
block.arch                     block.disassembly              block.parse_from_cmessage(     block.serialize_to_cmessage()  block.vex 
block.bytes                    block.instruction_addrs        block.pp(     
```



##### State 模块



示例->

```text
>>> state=project.factory.entry_state()
<SimState @ 0x8048450>
>>> state.regs.eip 
<BV32 0x8048450>
>>> state.mem[project.entry].int.resolved 
<BV32 0x895eed31>
>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved 
<BV32 0x4>
```



这个 state 包括了符号实行中所需要的所有符号。



通过 state.regs.eip 可以看出，所有的寄存器都会替换为一个符号。该符号可以由模块自行推算，也可以人为的进行更改。也正因如此，Angr 能够通过条件约束对符号的值进行解方程，从而去计算输入，比如说：

```text
>>> bv = state.solver.BVV(0x2333, 32)        
<BV32 0x2333>
>>> state.solver.eval(bv) 
9011(hex->0x2333)
```



另外还存在一些值，它只有在运行时才能够得知，对于这些值，Angr 会将它标记为 UNINITIALIZED ：

```text
>>> state.regs.edi 
WARNING  | 2023-04-12 17:28:41,490 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing register with an unspecified value. This could indicate 
unwanted behavior.
WARNING  | 2023-04-12 17:28:41,491 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and con 
tinuing. You can resolve this by:
WARNING  | 2023-04-12 17:28:41,491 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state 
WARNING  | 2023-04-12 17:28:41,492 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make un 
known regions hold null
WARNING  | 2023-04-12 17:28:41,492 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppr 
ess these messages.
WARNING  | 2023-04-12 17:28:41,492 | angr.storage.memory_mixins.default_filler_mixin | Filling register edi with 4 unconstrained bytes referenced from 0x8048450 (_start +0x0 in 02_angr_find_condition (0x8048450))
<BV32 reg_edi_1_32{UNINITIALIZED}>
```



另外值得一提的是，除了 entry_state 外还有其他状态可用于初始化：

**blank_state**：构造一个“空白板”空白状态，其中大部分数据未初始化。当访问未初始化的数据时，将返回一个不受约束的符号值。

**entry_state**：造一个准备在主二进制文件的入口点执行的状态。

**full_init_state**：构造一个准备好通过任何需要在主二进制文件入口点之前运行的初始化程序执行的状态，例如，共享库构造函数或预初始化程序。完成这些后，它将跳转到入口点。

**call_state**：构造一个准备好执行给定函数的状态。



这些构造函数都能通过参数 addr 来指定初始时的 rip/eip 地址。而 call_state 可以用这种方式来构造传参：call_state(addr, arg1, arg2, ...)



##### Simulation Managers 模块



SM(Simulation Managers)是一个用来管理 State 的模块，它需要为符号指出如何运行。

```text
>>> simgr = project.factory.simulation_manager(state) 
<SimulationManager with 1 active> 
>>> simgr.active 
[<SimState @ 0x8048450>]
```



通过 step 可以让这组模拟执行一个基本块：

```text
>>> simgr.step() 
<SimulationManager with 1 active> 
>>> simgr.active 
[<SimState @ 0x8048420>]
>>> simgr.active[0].regs.eip 
<BV32 0x8048420>
```



此时的 eip 对应了 __libc_start_main 的地址。



同样也可以查看此时的模拟内存状态，可以发现它储存了函数的返回地址：

```text
>>> simgr.active[0].mem[simgr.active[0].regs.esp].int.resolved    
<BV32 0x8048471>
```



而我们比较熟悉的 simgr 其实就是 simulation_manager 简写：

```text
>>> project.factory.simgr() 
<SimulationManager with 1 active> 
>>> project.factory.simulation_manager()                           
<SimulationManager with 1 active>
```



##### SimProcedure

在前文中提到过 Angr 会 hook 一些常用的库函数来提高效率。它支持一下这些外部库：

```text
>>> angr.procedures. 
angr.procedures.SIM_LIBRARIES   angr.procedures.glibc           angr.procedures.java_util       angr.procedures.ntdll           angr.procedures.uclibc 
angr.procedures.SIM_PROCEDURES  angr.procedures.gnulib          angr.procedures.libc            angr.procedures.posix           angr.procedures.win32 
angr.procedures.SimProcedures   angr.procedures.java            angr.procedures.libstdcpp       angr.procedures.procedure_dict  angr.procedures.win_user32 
angr.procedures.advapi32        angr.procedures.java_io         angr.procedures.linux_kernel    angr.procedures.stubs             
angr.procedures.cgc             angr.procedures.java_jni        angr.procedures.linux_loader    angr.procedures.testing           
angr.procedures.definitions     angr.procedures.java_lang       angr.procedures.msvcr           angr.procedures.tracer
```



以 libc 为例就可以看到，它支持了一部分 libc 中的函数：

```text
>>> angr.procedures.libc. 
angr.procedures.libc.abort      angr.procedures.libc.fprintf    angr.procedures.libc.getuid     angr.procedures.libc.setvbuf    angr.procedures.libc.strstr 
angr.procedures.libc.access     angr.procedures.libc.fputc      angr.procedures.libc.malloc     angr.procedures.libc.snprintf   angr.procedures.libc.strtol
......
由于函数过多，这里就不展示了
```



因此如果程序中调用了这部分函数，默认情况下就会由 angr.procedures.libc 中实现的函数进行接管。但是请务必注意，官方文档中也有提及，一部分函数的实现并不完善，比如说对 scanf 的格式化字符串支持并不是很好，因此有的时候需要自己编写函数来 hook 它。



##### hook 模块

紧接着上文提到的问题，Angr 接受由用户自定义函数来进行 hook 的操作。

```text
>>> func=angr.SIM_PROCEDURES['libc']['scanf']
>>> project.hook(0x10000, func())
>>> project.hooked_by(0x10000)     
<SimProcedure scanf>
>>> project.unhook(0x10000)
>>> project.hooked_by(0x10000) 
WARNING  | 2023-04-12 19:20:39,782 | angr.project   | Address 0x10000 is not hooked
```



第一种方案是直接对地址进行 hook，通过直接使用 project.hook(addr,function()) 的方法直接钩取。

同时，Angr 对于有符号的二进制程序也运行直接对符号本身进行钩取：project.hook_symbol(name,function) 



##### 结语

***对于angr_ctf中的题解可以参考：***

[[原创\] Angr 使用技巧速通笔记(二)-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-276860.htm)

[angr符号执行练习 00_angr_find_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV167411o7WK/?t=1043)

https://github.com/jakespringer/angr_ctf/blob/master/SymbolicExecution.pptx





### 干扰分析技术



#### 花指令



#### 反调试



#### 壳保护



##### UPX

先把程序拖到upx.exe所在文件夹
打开cmd
输入d:回车
输入cd空格upx的路径 回车
输入upx.exe -h 回车

之后进行脱壳加壳：
upx -d空格+文件名



或者用**UPX一键脱壳**



##### ESP脱壳

分析文件可知是魔改壳，使用32dbg工具再ESP脱壳

![](./assets/1.png)

我们F9运行后再F8单步运行至mov指令

![](./assets/2.png)

我们再右键ESP点击转储中跟随

![](./assets/3.png)

在左下角的地址右键下断点

然后F9运行之后F8跳转之后的call指令就是程序入口了

![](./assets/4.png)

然后我们进行dump数据

![](./assets/5.png)

我们dump之后还需要fix这个数据

![](./assets/6.png)

最后得到脱壳完毕的exe文件

![](./assets/7.png)

#### 控制流混淆



#### 双进程保护



#### 虚拟机保护



#### shellcode



**Shellcode类题常常需要利用数据构造文件，在所构造的文件中进行二次解密再得到flag，常规类题目需要观察 Hex部分 / 已给的密文 是否有文件信息，根据题目给的提示来判断是否为shellcode再进行构造**



例题-->**[HGAME 2023]shellcode**



根据这个题目名称我们便有了思路  开始寻找shellcode

我们进入ida先搜索是否有main函数

直接跟进

![图片](./assets/640.png)

可以发现有一个函数名叫encoding_base64 ，那根据下方的base64编码便能推测此处为被加密的shellcode代码。我们将此处的base64代码复制下来，在010中选择 **粘贴自Base64。**

![图片](./assets/640-1692352835431-3.png)yo

保存文件后用ida32打开

![图片](./assets/640-1692352863240-6.png)

一个魔改的TEA

``

```cpp
# include<iostream>
# include<algorithm>
# include<cstdio>
# include<cmath>
# include<map>
# include<vector>
# include<queue>
# include<stack>
# include<set>
# include<string>
# include<cstring>
# include<list>
# include<stdlib.h>
using namespace std;
int main(){        
char v1[41] = { 0x48, 0x67, 0x45, 0x51, 0x42, 0x7b, 0x70, 0x6a, 0x30, 0x68, 0x6c, 0x60, 0x32, 0x61, 0x61, 0x5f, 0x42, 0x70,0x61, 0x5b, 0x30, 0x53, 0x65, 0x6c, 0x60, 0x65, 0x7c, 0x63, 0x69, 0x2d, 0x5f, 0x46, 0x35, 0x70, 0x75,0x7d };    
unsigned int v0 = strlen(v1);    int v2;    int v3;    int v4;    int v5;    int v6;    int i;
    for (i = 0; i < 37; ++i){        
    	if (v0 <= i)            
    	break;
        v6 = i % 5;        
        if (i % 5 == 1){
        v1[i] ^= 35;        
        }        
        else
        {
        switch (v6)            
        {                
            case 2:                    
                v1[i] -= 2;
                break;
            case 3:
                v1[i] += 3;
                break;
            case 4:
                v1[i] += 4;
                break;
            case 5:
                v1[i] += 125;
                break;
        }
        }
    }
    printf("%s", v1);}
```



#### 虚拟机逆向

**遇见vm-re的题目，先查找到opcode(伪机器码)，然后找到dispatcher(就是模拟CPU读取指令的分发器)，然后边分析那些伪汇编函数(就是模仿汇编指令的函数)边查找模拟的CPU的栈，寄存器，全局变量(多是字符串)等**



虚拟机逆向少不了opcode，整个虚拟机逆向少不了对opcode的操作，我们的核心就是针对于数据进行解密

接下来给两个虚拟机re对opcode操作的脚本



**[HGAME 2023]**

``

```python
data1 = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9B, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0xBC, 0x00, 0x00, 0x00, 0xAC, 0x00, 0x00, 0x00,
    0x9C, 0x00, 0x00, 0x00, 0xCE, 0x00, 0x00, 0x00, 0xFA, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00, 0x00, 0x74, 0x00,
    0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x69, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0xCB, 0x00, 0x00, 0x00, 0xC9, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0x00, 0xFC, 0x00, 0x00, 0x00, 0x80, 0x00,
    0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00,
    0xD7, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xA7, 0x00, 0x00, 0x00, 0x1D, 0x00, 0x00, 0x00,
    0x3D, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x88, 0x00,
    0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x00,
    0xE8, 0x00, 0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0x2E, 0x00,
    0x00, 0x00, 0x5D, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC9, 0x00, 0x00, 0x00, 0xA9, 0x00, 0x00, 0x00, 0xBD, 0x00,
    0x00, 0x00, 0x8B, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
    0xC2, 0x00, 0x00, 0x00, 0x6E, 0x00, 0x00, 0x00, 0xF8, 0x00,
    0x00, 0x00, 0xF5, 0x00, 0x00, 0x00, 0x6E, 0x00, 0x00, 0x00,
    0x63, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0xD5, 0x00,
    0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x5D, 0x00, 0x00, 0x00,
    0x16, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x38, 0x00,
    0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0xC1, 0x00, 0x00, 0x00, 0x5E, 0x00,
    0x00, 0x00, 0xED, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00,
    0x29, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x18, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xA7, 0x00, 0x00, 0x00,
    0xFD, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x1E, 0x00,
    0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x8B, 0x00, 0x00, 0x00,
    0x62, 0x00, 0x00, 0x00, 0xDB, 0x00, 0x00, 0x00, 0x0F, 0x00,
    0x00, 0x00, 0x8F, 0x00, 0x00, 0x00, 0x9C, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
data2=[
    0x00, 0x48, 0x00, 0x00, 0x00, 0xF1, 0x00, 0x00, 0x00, 0x40,
    0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x01, 0x35, 0x00, 0x00,
    0x00, 0x64, 0x00, 0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0xF9,
    0x00, 0x00, 0x01, 0x18, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00,
    0x00, 0x25, 0x00, 0x00, 0x01, 0x5D, 0x00, 0x00, 0x00, 0x47,
    0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x01, 0x69, 0x00, 0x00,
    0x00, 0x5C, 0x00, 0x00, 0x01, 0xAF, 0x00, 0x00, 0x00, 0xB2,
    0x00, 0x00, 0x01, 0xEC, 0x00, 0x00, 0x01, 0x52, 0x00, 0x00,
    0x01, 0x4F, 0x00, 0x00, 0x01, 0x1A, 0x00, 0x00, 0x00, 0x50,
    0x00, 0x00, 0x01, 0x85, 0x00, 0x00, 0x00, 0xCD, 0x00, 0x00,
    0x00, 0x23, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x0C,
    0x00, 0x00, 0x00, 0xCF, 0x00, 0x00, 0x01, 0x3D, 0x00, 0x00,
    0x01, 0x45, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x01, 0xD2,
    0x00, 0x00, 0x01, 0x29, 0x00, 0x00, 0x01, 0xD5, 0x00, 0x00,
    0x01, 0x06, 0x00, 0x00, 0x01, 0xA2, 0x00, 0x00, 0x00, 0xDE,
    0x00, 0x00, 0x01, 0xA6, 0x00, 0x00, 0x01, 0xCA, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]

data=[]

for i in range(0, len(data1), 4):
    #print((data1[i]),end=',')
    data.append(data1[i])

for i in range(0,len(data2) ,4):
    value = (data2[i+1] << 8) | data2[i]
    #print((value),end=',')
    data.append(value)


opcode=[  0x00, 0x03, 0x02, 0x00, 0x03, 0x00, 0x02, 0x03, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x02, 0x32,
  0x03, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
  0x01, 0x00, 0x00, 0x03, 0x02, 0x64, 0x03, 0x00, 0x02, 0x03,
  0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x01, 0x00, 0x00, 0x03,
  0x00, 0x08, 0x00, 0x02, 0x02, 0x01, 0x03, 0x04, 0x01, 0x00,
  0x03, 0x05, 0x02, 0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x02,
  0x00, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x01, 0x03, 0x00,
  0x03, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03, 0x01, 0x28,
  0x04, 0x06, 0x5F, 0x05, 0x00, 0x00, 0x03, 0x03, 0x00, 0x02,
  0x01, 0x00, 0x03, 0x02, 0x96, 0x03, 0x00, 0x02, 0x03, 0x00,
  0x00, 0x00, 0x00, 0x04, 0x07, 0x88, 0x00, 0x03, 0x00, 0x01,
  0x03, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03,
  0x01, 0x28, 0x04, 0x07, 0x63, 0xFF, 0xFF, 0x00]
ip=0
def mov():
    global opcode, ip
    match opcode[ip + 1]:
        case 0:
            print("mov reg[0],data[reg[2]]")
        case 1:
            print("mov data[reg[2]],reg[0]")
        case 2:
            print(f"mov reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
        case 3:
            print(f"mov reg[{opcode[ip + 2]}],{opcode[ip + 3]}")
    ip += 4


def push():
    global opcode, ip
    match opcode[ip + 1]:
        case 0:
            print("push reg[0]")
        case 1:
            print("push reg[0]")
        case 2:
            print("push reg[2]")
        case 3:
            print("push reg[3]")
    ip += 2


def pop():
    global opcode, ip
    match opcode[ip + 1]:
        case 0:
            print("pop reg[0]")
        case 1:
            print("pop reg[0]")
        case 2:
            print("pop reg[2]")
        case 3:
            print("pop reg[3]")
    ip += 2


def alu():
  global opcode, ip
  match opcode[ip + 1]:
      case 0:
        print(f"add reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
      case 1:
        print(f"sub reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
      case 2:
        print(f"mul reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
      case 3:
        print(f"xor reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
      case 4:
        print(f"shl reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
      case 5:
        print(f"shr reg[{opcode[ip + 2]}],reg[{opcode[ip + 3]}]")
  ip += 4


def cmp():
    global opcode, ip
    print("cmp reg[0],reg[1]")
    ip += 1


def jmp():
    global opcode, ip
    print(f"jmp {opcode[ip + 1]}")
    ip += 2


def jne():
    global opcode, ip
    print(f"jne {opcode[ip + 1]}")
    ip += 2


def je():
    global opcode, ip
    print(f"je {opcode[ip + 1]}")
    ip += 2

while opcode[ip] != 0xFF:
  match opcode[ip]:
      case 0:
        mov()
      case 1:
        push()
      case 2:
        pop()
      case 3:
        alu()
      case 4:
        cmp()
      case 5:
        jmp()
      case 6:
        jne()
      case 7:
        je()

for i in range(40):
    num=data[150+39-i]
    #print(hex(num))
    num=(((num<<8)&0xFF00)+((num>>8)&0xFF))&0xFFFF
    num^=data[i+100]
    num-=data[i+50]
    print(chr(num),end="")
```



**[GWCTF 2019]**

``

```python
opcode=[0xF5, 0xF1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4,
  0x20, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x01, 0x00, 0x00, 0x00,
  0xF2, 0xF1, 0xE4, 0x21, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x02,
  0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x22, 0x00, 0x00, 0x00,
  0xF1, 0xE1, 0x03, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x23,
  0x00, 0x00, 0x00, 0xF1, 0xE1, 0x04, 0x00, 0x00, 0x00, 0xF2,
  0xF1, 0xE4, 0x24, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x05, 0x00,
  0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x25, 0x00, 0x00, 0x00, 0xF1,
  0xE1, 0x06, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x26, 0x00,
  0x00, 0x00, 0xF1, 0xE1, 0x07, 0x00, 0x00, 0x00, 0xF2, 0xF1,
  0xE4, 0x27, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x08, 0x00, 0x00,
  0x00, 0xF2, 0xF1, 0xE4, 0x28, 0x00, 0x00, 0x00, 0xF1, 0xE1,
  0x09, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x29, 0x00, 0x00,
  0x00, 0xF1, 0xE1, 0x0A, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4,
  0x2A, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x0B, 0x00, 0x00, 0x00,
  0xF2, 0xF1, 0xE4, 0x2B, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x0C,
  0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x2C, 0x00, 0x00, 0x00,
  0xF1, 0xE1, 0x0D, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x2D,
  0x00, 0x00, 0x00, 0xF1, 0xE1, 0x0E, 0x00, 0x00, 0x00, 0xF2,
  0xF1, 0xE4, 0x2E, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x0F, 0x00,
  0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x2F, 0x00, 0x00, 0x00, 0xF1,
  0xE1, 0x10, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x30, 0x00,
  0x00, 0x00, 0xF1, 0xE1, 0x11, 0x00, 0x00, 0x00, 0xF2, 0xF1,
  0xE4, 0x31, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x12, 0x00, 0x00,
  0x00, 0xF2, 0xF1, 0xE4, 0x32, 0x00, 0x00, 0x00, 0xF1, 0xE1,
  0x13, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x33, 0x00, 0x00,
  0x00, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF5, 0xF1,
  0xE1, 0x00, 0x00, 0x00, 0x00, 0xF1, 0xE2, 0x01, 0x00, 0x00,
  0x00, 0xF2, 0xF1, 0xE4, 0x00, 0x00, 0x00, 0x00, 0xF1, 0xE1,
  0x01, 0x00, 0x00, 0x00, 0xF1, 0xE2, 0x02, 0x00, 0x00, 0x00,
  0xF2, 0xF1, 0xE4, 0x01, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x02,
  0x00, 0x00, 0x00, 0xF1, 0xE2, 0x03, 0x00, 0x00, 0x00, 0xF2,
  0xF1, 0xE4, 0x02, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x03, 0x00,
  0x00, 0x00, 0xF1, 0xE2, 0x04, 0x00, 0x00, 0x00, 0xF2, 0xF1,
  0xE4, 0x03, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x04, 0x00, 0x00,
  0x00, 0xF1, 0xE2, 0x05, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4,
  0x04, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x05, 0x00, 0x00, 0x00,
  0xF1, 0xE2, 0x06, 0x00, 0x00, 0x00, 0xF2, 0xF1, 0xE4, 0x05,
  0x00, 0x00, 0x00, 0xF1, 0xE1, 0x06, 0x00, 0x00, 0x00, 0xF1,
  0xE2, 0x07, 0x00, 0x00, 0x00, 0xF1, 0xE3, 0x08, 0x00, 0x00,
  0x00, 0xF1, 0xE5, 0x0C, 0x00, 0x00, 0x00, 0xF6, 0xF7, 0xF1,
  0xE4, 0x06, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x07, 0x00, 0x00,
  0x00, 0xF1, 0xE2, 0x08, 0x00, 0x00, 0x00, 0xF1, 0xE3, 0x09,
  0x00, 0x00, 0x00, 0xF1, 0xE5, 0x0C, 0x00, 0x00, 0x00, 0xF6,
  0xF7, 0xF1, 0xE4, 0x07, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x08,
  0x00, 0x00, 0x00, 0xF1, 0xE2, 0x09, 0x00, 0x00, 0x00, 0xF1,
  0xE3, 0x0A, 0x00, 0x00, 0x00, 0xF1, 0xE5, 0x0C, 0x00, 0x00,
  0x00, 0xF6, 0xF7, 0xF1, 0xE4, 0x08, 0x00, 0x00, 0x00, 0xF1,
  0xE1, 0x0D, 0x00, 0x00, 0x00, 0xF1, 0xE2, 0x13, 0x00, 0x00,
  0x00, 0xF8, 0xF1, 0xE4, 0x0D, 0x00, 0x00, 0x00, 0xF1, 0xE7,
  0x13, 0x00, 0x00, 0x00, 0xF1, 0xE1, 0x0E, 0x00, 0x00, 0x00,
  0xF1, 0xE2, 0x12, 0x00, 0x00, 0x00, 0xF8, 0xF1, 0xE4, 0x0E,
  0x00, 0x00, 0x00, 0xF1, 0xE7, 0x12, 0x00, 0x00, 0x00, 0xF1,
  0xE1, 0x0F, 0x00, 0x00, 0x00, 0xF1, 0xE2, 0x11, 0x00, 0x00,
  0x00, 0xF8, 0xF1, 0xE4, 0x0F, 0x00, 0x00, 0x00, 0xF1, 0xE7,
  0x11, 0x00, 0x00, 0x00, 0xF4]

reg = {0xe1:'eax',0xe2:'ebx',0xe3:'ecx',0xe5:'edx'}

operation = {0xf1:'mov',0xf2:'xor',0xf5:'read',0xf4:'nop',0xf7:'add',0xf8:'swap',0xf6:'mul'}

i = 0
for j in range(len(opcode)):
    if(opcode[i] == 0xF1 ):
        print('mov ',end='')
        if (opcode[i+1] == 0xe1):
            print('eax ' + 'flag[' + str(opcode[i + 2]) + ']')
        elif(opcode[i+1] == 0xe2):
            print('ebx '+'flag['+str(opcode[i+2])+']')
        elif(opcode[i+1] == 0xe3):
            print('ecx ','flag['+str(opcode[i+2])+']')
        elif(opcode[i+1] == 0xe4):
            print('flag['+str(opcode[i+2])+'] '+'eax')
        elif(opcode[i+1] == 0xe5):
            print('edx '+'flag['+str(opcode[i+2])+']')
        elif(opcode[i+1] == 0xe7):
            print('flag['+str(opcode[i+2])+'] '+'ebx')
        i+=6
    elif(opcode[i] == 0xf2):
        print('xor eax ecx')
        i+=1
    elif(opcode[i] == 0xf5):
        print('read')
        i+=1
    elif(opcode[i] == 0xf4):
        print('nop')
        i+=1
    elif(opcode[i] == 0xf7):
        print('eax=eax*ecx')
        i+=1
    elif(opcode[i] == 0xf8):
        print('swap eax ebx')
        i+=1
    elif(opcode[i] == 0xf6):
        print('mul eax=ecx+2*ebx+3*eax')
        i+=1
    else:
        i+=1
```



## 安卓逆向



### APK文件结构

APK是Android Package的缩写，即Android安装包，所有的Android程序都是以APK文件的形式发布的。可以在模拟器或手机上运行APK文件来安装程序。APK文件的后缀为．apk，但是其格式是压缩文件zip的格式。可以通过WinZip、WinRAR等将其解压



**简述版：**

- META-INF文件夹：签名文件目录
- res文件夹：资源库目录 一般存放xml布局文件和图标
- AndroidMainifest.xml ：配置清单（二进制格式）
- classes.dex：安卓系统上的可执行文件，也是我们逆向的主要的文件，源码都被编译在里面，如有多个是因为每个dex里最多存放65535个方法，而项目的方法数超出了这个数量，所以被分成多个保存
- resources.arsc：资源索引文件，包含语言包，汉化的话一般是反编译这个文件
- assets ：资源目录，一般存放图片
- lib：是动态库目录 一般存放so文件

![在这里插入图片描述](./Reverse.assets/watermark.png)

#### 1. **静态资源文件**

静态资源文件主要指存放在assets 文件夹中的文件。assets 文件夹是一种未经编译的资源目录，它会被打包进 APK 文件中，在安装应用程序之后可以被访问。assets 文件夹中的文件不会被解压缩，这意味着它们的访问速度会比较快，但是会占用更多的安装包空间。通常情况下，开发者会将应用程序中的静态文件、配置文件、原始数据或者其他不常改变的文件放在 assets 文件夹中。这样可以使得应用程序的下载包大小变小，并且可以更快速地访问这些文件。

#### 2.**库文件**

库文件主要指lib文件夹中的文件，在这个文件夹中，存放了运行APP所需要的so文件，也就是动态链接库的二进制文件。为了适配不同安卓系统处理器的版本，lib文件夹中的so库也是按不同处理器版本的文件夹分类放置。在图3的示例中，分成了三种文件夹包括armeabi、armeabi-v7a和x86文件夹，分别用来存储适配arm5架构、arm7架构、Intel32架构的CPU处理器版本的安卓系统。例如，如果智能手机使用的是arm7架构CPU处理器版本的安卓系统，APP在运行时就会调用armeabi-v7a文件夹下的动态链接库文件执行程序。

在安卓系统中库文件分文两种，一种是共享库文件（Shared Libraries），另一种是**本地库文件（Native Libraries）**。共享库文件是可供多个应用程序使用的库，它们被存放在系统目录中。在 Android 系统中，共享库文件以 .so 为后缀，常见的共享库文件包括 libc.so 和 libm.so。

而lib文件夹存放的就是本地库文件。本地库是专门为应用程序所使用的库，它们被打包进 APK 文件中，在安装应用程序之后会被放到私有目录中。在 Android 系统中，本地库文件也以 .so 为后缀。对于一个 Android 应用程序来说，本地库文件往往是应用程序所特有的，并且不会被其他应用程序使用。例如，**一个应用程序可能使用本地库文件来封装特定的硬件访问功能，或者使用本地库文件来进行加密解密操作。**

#### 3.签名文件

签名文件指的是存放在META-INF文件夹中的文件。META-INF 文件夹是 Android 系统中的一种特殊文件夹，它用来存放应用程序的签名信息。在 META-INF 文件夹中可以找到三种常见的文件：CERT.RSA、CERT.SF和MANIFEST.MF。CERT.RSA、CERT.SF这两个文件用来存放应用程序的签名信息。当安装一个应用程序时，Android 系统会检查这两个文件，以确保应用程序的完整性和安全性。MANIFEST.MF文件用来存放应用程序的所有文件的清单信息。

当打包应用程序时，这些文件会自动生成，并且会被打包进 APK 文件中。通常情况下，不需要手动修改这些文件，但是有时候可能需要编辑这些文件来更新应用程序的版本号或者修改权限要求。

META-INF文件夹，用于存放签名证书，在APK安装时作为校验的凭据，用于保护APK不被恶意篡改，同时也是对APK著作权和所有权的声名。例如，对安装包的任意文件最作修改，导致安卓系统检查计算后的签名信息与APK文件中存储的签名信息不一致，最终无法安装，会出现签名冲突的问题。

#### 4.编译资源文件

编译资源文件主要指存放在res文件夹中的文件。res文件夹，存放的也是资源文件，与assets文件夹不同的是，这里是编译后的资源文件。直接打开可能显示乱码。在 res 文件夹中你会找到许多子文件夹，每个子文件夹都用来存放特定类型的资源文件。主要的文件夹包括drawable 文件夹、layout 文件夹和values 文件夹。

drawable 文件夹用来存放图片资源文件，包括位图文件（.png, .jpg, .gif 等）和矢量图文件（.svg）。

layout 文件夹用来存放布局文件，布局文件用来描述应用程序的界面结构。

values 文件夹用来存放值资源文件，值资源文件用来存放应用程序中使用的常量值和颜色信息。

在 Android 系统中，所有的资源文件都必须在 res 文件夹中存放，并且需要使用特定的文件名和文件夹名。这样的好处是，Android 系统会自动为每个资源文件分配一个唯一的资源 ID，使得安卓系统可以方便地引用这些资源。

#### **5.配置清单文件**

AndroidManifest.xml文件是配置清单文件，也是编译过的文件，用来描述应用程序的清单信息。包括包名、应用名、权限、安卓四大组件、版本等重要信息都在这里面声名。

当打包应用程序时，AndroidManifest.xml 文件会自动生成，并且会被打包进 APK 文件中。当你安装应用程序时，Android 系统会读取这个文件，以确定应用程序的基本信息和权限要求。

开发者可以在 AndroidManifest.xml 文件中声明应用程序使用的权限，例如访问网络、访问文件、访问相机等。在应用程序安装时，用户会看到这些权限的描述信息，然后决定是否允许应用程序使用这些权限。

AndroidManifest.xml 文件还用来声明应用程序的主要组件，例如活动（Activity）、服务（Service）、广播接收器（BroadcastReceiver）等。这些组件是安卓应用程序的四大组件的组成部分，它们负责实现应用程序的功能

#### 6.核心代码文件

核心代码文件主要指classes.dex文件。classes.dex文件是 Android 系统中的重要代码文件，它是 Dalvik 可执行文件的缩写。Dalvik 是 Android 系统中的一种虚拟机，它负责在 Android 系统中运行应用程序的代码。classes.dex文件运行在Dalvik虚拟机上的核心代码文件，它反编译后的语言是smali代码语言，smali代码可转换为java代码。对于大的APK文件会出现多个dex文件，但在APP实际运行的过程中会将多个dex文件合并成一个dex文件运行。APK打包时存放多个dex的原因是每个dex文件的大小是有限制的。

.dex 文件中存放的是 Java 字节码，这是 Java 编译器编译出来的机器码。.dex 文件本身是一种二进制文件，它使用一种特殊的格式来存放字节码。

在打包 Android 应用程序时，.dex 文件会自动生成，并且会被打包进 APK 文件中。当你安装应用程序时，.dex 文件会被解压缩并放到私有目录中，然后被 Dalvik 虚拟机加载并运行。

.dex 文件的好处是，它可以使得应用程序的下载包大小变小，因为 Java 字节码文件可以被压缩得比较小。但是 .dex 文件的缺点是，它的访问速度略慢于共享库文件。因此，在 Android 系统中，一般情况下会尽量使用共享库文件来实现应用程序的功能。

#### 7.资源映射文件 

resources.arsc 文件是 Android 系统中的一种特殊文件，它用来存放应用程序的资源表。资源表是一种二进制文件，它包含了应用程序的资源 ID 和资源类型的映射关系。

在 Android 系统中，所有的资源文件都必须在 res 文件夹中存放，并且需要使用特定的文件名和文件夹名。当你编译应用程序时，编译器会将 res 文件夹中的资源文件编译成资源表，并且将资源表打包进 APK 文件中。

resources.arsc 文件的好处是，它可以使得应用程序的资源文件变小，因为资源表文件可以被压缩得比较小。但是，resources.arsc 文件的缺点是，它的访问速度略慢于普通的文本文件。因此，在 Android 系统中，一般情况下会尽量使用普通的文本文件来存放应用程序的资源信息。

注意，resources.arsc 文件仅仅是一个**辅助文件**，它本身并没有什么实际意义。应用程序通常是通过资源 ID在这个资源映射表中寻找对应的资源，来获取相应的参数。

### adb的使用



Android开发环境中，ADB是我们进行Android开发经常要用的调试工具，它的使用当然是我们Android开发者必须要掌握的。



**一. ADB概述**

Android Debug Bridge，Android调试桥接器，简称adb，是用于管理模拟器或真机状态的万能工具，采用了客户端-服务器模型，包括三个部分：

1. 客户端部分，运行在开发用的电脑上，可以在命令行中运行adb命令来调用该客户端，像ADB插件和DDMS这样的Android工具也可以调用adb客户端。
2. 服务端部分，是运行在开发用电脑上的后台进程，用于管理客户端与运行在模拟器或真机的守护进程通信。
3. 守护进程部分，运行于模拟器或手机的后台。

**二. 如何找到adb？**

安装模拟器后，电脑桌面会有“模拟器”的启动图标，鼠标右键--打开文件所在的位置，就会进入***\模拟器名称\bin，比如我的路径是D:\Nox\bin，然后可以在该路径下找到nox_adb.exe

**三. 如何连接设备？**

首先需要进入\Nox\bin路径的cmd窗口。

*方式一*：继续上述的步骤，进入\Nox\bin目录，然后按Shift键的同时，单击鼠标右键，就会看到“在此处打开命令窗口(W)”，点击即可进入\Nox\bin路径的cmd窗口。

*方式二*：按Windows+R键，在弹出的“运行”窗口输入cmd，确定，然后输入cd C:\Program Files (x86)\Nox\bin（说明：这是你的夜神模拟器安装路径），即可。说明：如果你的夜神模拟器不是安装在C盘，比如安装在D盘，请在cd前面先输入D: 然后按回车键，再cd ......\Nox\bin。

在连接设备之前，先查看一下在运行的设备：

> `adb devices`
>
> C:\Program Files (x86)\Nox\bin>nox_adb devices
>
> List of devices attached
>
> 127.0.0.1:62001 device

**四. 常用adb操作介绍**

1. 如何把电脑上的文件或文件夹传到模拟器里面？

> adb push D:/sex.avi /mnt/avi/

2. 如何把模拟器里面的文件或文件夹传到电脑上？

> adb pull /mnt/avi/sex.avi D:/avi/

3. 安装APK

**adb install xxxx.apk**

4. 卸载APK

> adb uninstall 包名
>
> 比如卸载QQ：adb uninstall com.tencent.mobileqq



### 复杂加密



### HOOK技术



### 深层文件分析与其他技术



#### Native层逆向



##### OLLVM混淆及加密技术



##### -fla :control flow flattening（控制流平坦化）



##### -bcf :bogus control flow（控制流伪造）



##### -sub :instruction substitution(指令替换)



#### Dalvik层逆向



#### frida技术



##### 	windows环境构建

frida 是一款基于 python+javascript 的 hook 框架，可运行在 android、ios、linux、win等平台，主要使用的动态二进制插桩技术。

　　**Frida官网：https://www.frida.re/**

　　**Frida源码：https://github.com/frida**



Frida的安装很简单，需要在windows安装frida客户端和在安卓安装frida服务端

``

```python
pip install frida
pip install frida-tools

```

- 查看连接到的设备

```python
frida-ls-devices
```

##### 	手机环境构建

首先到github上下载frida-server，网址为https://github.com/frida/frida/releases，从网址可以看到，frida提供了各种系统平台的server，我的模拟器为三星galaxy note10，是x86，所以我下载的为x86的

　　查询手机对应的cpu

```
adb shell getprop ro.product.cpu.abi
```

![image-20230818165354743](./assets/image-20230818165354743.png)



注意是：***frida-server-版本号-平台-cpu架构***

![image-20230818165142042](./assets/image-20230818165142042.png)

我们解压之后可以使用adb命令push到手机中

```
adb  push  D:\Downloads\frida-server-16.1.3-android-x86  /data/local

#进入手机终端，修改文件权限并运行
adb shell

cd /data/local

chmod 777 frida-server-16.1.3-android-x86

./frida-server-16.1.3-android-x86
```

我们可以验证一下是否frida在程序中成功启动了

![image-20230818170758076](./assets/image-20230818170758076.png)

然后我们另外起一个终端

输入：frida-ps -U

![image-20230818171001498](./assets/image-20230818171001498.png)

我们可以看到frida在手机端也成功启动了



## 脚本语言逆向



### Python程序逆向



#### pyc反编译



#### 字节码分析



#### Python解包



### .NET程序逆向



#### 程序包编译



#### 程序反混淆



### Java程序逆向



#### jar包提取



#### jar包反编译



### C#程序逆向



## 工具

### IDA Pro



#### ida python



#### 远程调试



### Jadx



### dnspy



### od/dbg



### 其他



#### CE



##### 数据跟踪







#### AndroidKiller



#### Pyinstxtractor



## 其他题型

### 二叉树/抽象语法树



### 迷宫逆向

``

```python
#import idc,ida_bytes,ida_ida
import numpy as np
from queue import Queue
get=lambda x:str(idc.get_wide_byte(x))
map_addr=0x407040    
map=[]
for i in range(16):
    tmp=[]
    for j in range(16):
        tmp.append(get(map_addr))
        map_addr+=1
    map.append(tmp)


def generate_maze(width, height, start=[0,0], end=None, path_char='0',wall_char='1',difficult=0.3):
    if end is None:
        end=[width-1,height-1]
    maze = np.full((height, width), path_char)
    maze[start[1], start[0]] = 'S'
    maze[end[1], end[0]] = 'E'
    for row in range(height):
        for col in range(width):
            if maze[row, col] == path_char:
                maze[row, col] = wall_char if np.random.random() < difficult else path_char
    return maze
def find_shortest_path(maze,start=[0,0],end=None, wall_char='1'):
    if end is None:
        end=[len(maze[0])-1,len(maze)-1]
    queue = Queue()
    queue.put([start])
    visited = set(tuple(start))
    while not queue.empty():
        path = queue.get()
        current_pos = path[-1]
        if current_pos == end:
            return path
        row, col = current_pos[1], current_pos[0]
        neighbors = [[col, row-1], [col, row+1], [col-1, row], [col+1, row]]
        for neighbor in neighbors:
            x, y = neighbor
            if 0 <= x < maze.shape[1] and 0 <= y < maze.shape[0] and maze[y, x] != wall_char and tuple(neighbor) not in visited:
                queue.put(path + [neighbor])
                visited.add(tuple(neighbor))
    return []
def pr_maze(maze):
    print("迷宫:")
    for row in maze:
        print(''.join(row))
def pr_solve(maze,path):
    if path:
        print("最短路径:")
        for step in path:
            print("(%d,%d)-->"%(step[0],step[1]),end="")
            maze[step[1], step[0]] = '*'
        print("end\n")
        print("模拟行走:")
        for row in maze:
            print(''.join(row))
        print("\n")
        print("按键控制:") 
        for i in range(1,len(path)):
            if path[i][0]==path[i-1][0] :
                if  path[i][1] == path[i-1][1]+1:
                    print('s',end="")
                else:
                    print('w',end="")
            if path[i][1]==path[i-1][1]:
                if path[i][0]==path[i-1][0]+1:
                    print('d',end="")
                else:
                    print("a",end="")
    else:
        print("无法找到路径！")


map=np.array(map)
pr_solve(map,find_shortest_path(map,[1,15],[15,13]))
```

### 内存映射和动调调用



### Windows API







### DFS BFS



### CRC



### Swift

