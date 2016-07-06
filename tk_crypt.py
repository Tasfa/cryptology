# -*- coding:utf-8 -*-
#__author__:Tasfa


from Tkinter import *
from pyDes import *
import base64
import mymd5 
import AES




global flag
flag = 1

def des_encrypt():
    global flag
    flag =0
    global k
    #key_des = "Tasfa123"
    key_des = key_text.get()
    k = des(key_des, CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    text = plain_text.get()
    global miwen_des
    miwen_des=k.encrypt(text)
    miwen = "DES加密结果(base64)是：" + base64.b64encode(miwen_des)
    Label(root,text = miwen).grid(row=2,column=0)


def des_decrypt():
    if flag==0:
        mingwen1="DES解密结果是："+k.decrypt(miwen_des)
        Label(root,text = mingwen1).grid(row=3,column=0)
    else:
        try:
            crypt_text1=base64.b64decode(crypt_text.get())
            mingwen="DES解密结果是："+k.decrypt(crypt_text1)
            Label(root,text = mingwen).grid(row=3,column=0)
        except:
            error = Tk()
            error.geometry('200x50+500+350')
            Label(error,text = "请输入base64编码，重新输入！").pack()
            error.mainloop()

def aes_encrypt():
    key = key_text.get()#24
    if len(key) !=24:
        error = Tk()
        error.geometry('200x50+500+350')
        Label(error,text = "请输入24长度的KEY，重新输入！").pack()
        error.mainloop()
    key = [ord(ch) for ch in key]
    a = AES.AES(key)

    text = plain_text.get()#16
    if len(text) !=16:
        error = Tk()
        error.geometry('200x50+500+350')
        Label(error,text = "请输入16长度的明文，重新输入！").pack()
        error.mainloop()

    listOfBytes = []
    block = [ord(byte) for byte in list(text)]
    listOfBytes += a.encrypt(block)
    
    st = ''
    for byte in listOfBytes:
        st += chr(byte) 
    str = "AES加密结果是：" + base64.b64encode(st)
    Label(root,text = str).grid(row=4,column=0)  


def aes_decrypt():
    key = key_text.get()#24
    if len(key) !=24:
        error = Tk()
        error.geometry('200x50+500+350')
        Label(error,text = "请输入24长度的KEY，重新输入！").pack()
        error.mainloop()
    key = [ord(ch) for ch in key]
    a = AES.AES(key)

    text = crypt_text.get()#16
    text = base64.b64decode(text)
    if len(text) !=16:
        error = Tk()
        error.geometry('200x50+500+350')
        Label(error,text = "请输入16长度的密文(base64编码)，重新输入！").pack()
        error.mainloop()
    listOfBytes = []
    block = [ord(byte) for byte in list(text)]
    
    listOfBytes += a.decrypt(block)
    
    st = ''
    for byte in listOfBytes:
        st += chr(byte) 
    str = "AES解密结果是：" + st
    Label(root,text = str).grid(row=5,column=0)  


def md5():
    text = plain_text.get()
    miwen = "Md5 Hash 结果是： "+ mymd5.calc_md5(text)
    Label(root,text = miwen).grid(row=6,column=0)


global root
root = Tk()
root.wm_title("密码学实验GUI程序--Tasfa")

b1 = Button(root,text = "DES加密",command = des_encrypt)
b2 = Button(root,text = "DES解密",command = des_decrypt)
b3 = Button(root,text = "AES加密",command = aes_encrypt)
b4 = Button(root,text = "AES解密",command = aes_decrypt)
b5 = Button(root,text = "MD5 hsah",command = md5)

Label(root,text="明文：").grid(row=0,column=0,sticky=E)
plain_text = Entry(root)
plain_text.grid(row=0,column=1)

Label(root,text="密文：").grid(row=0,column=2,sticky=E)
crypt_text = Entry(root)
crypt_text.grid(row=0,column=3)

Label(root,text="密钥：").grid(row=0,column=4,sticky=E)
key_text = Entry(root)
key_text.grid(row=0,column=5)

b1.grid(row=1,column=1,sticky=E)
b2.grid(row=1,column=2,sticky=E)
b3.grid(row=1,column=3,sticky=E)
b4.grid(row=1,column=4,sticky=E)
b5.grid(row=1,column=5,sticky=E)



root.geometry('1000x200+300+300') #widthxhigh代表了初始化时主窗口的大小，+代表了初始化时窗口所在的位置
root.mainloop()
