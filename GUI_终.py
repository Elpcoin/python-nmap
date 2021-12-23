#!/usr/bin/env python3
from itertools import islice  # 导入 islice 使用迭代器处理文件
from tkinter import *
import tkinter as tk
import nmap                   #引入 nmap 模块

nm = nmap.PortScanner() #创建 portscanner 类

#重新定义输出函数以打印在 printText 中
def prin(usera):
   printText.insert(INSERT,usera)   # printText的插入语句
   return 0

#主机扫描同时进行os识别 标准输入是 192.168.1.1/29 同时可以只输入单个主机  *很慢我知道你扫少一点 要不就删掉os好吧
def test_file1(ip):
   prin('--------------------------------------------------\n')   
   x = '1                  主机扫描：\n'
   prin(x)
   prin('--------------------------------------------------\n\n')   
#  initial-rtt-timeout初始值为200ms,然后nmap会自动在min-rtt-timeout和max-rtt-timeout之间进行调整  --min-parallelism调整探测报文的并行度
   nm.scan(hosts=ip, arguments="--min-parallelism 10 --initial-rtt-timeout 200ms --min-rtt-timeout 150ms --max-rtt-timeout 300ms -sP") 
   for x in nm.all_hosts():       # 遍历存活主机
      result = nm.scan(hosts=x,arguments='-O',sudo=True) # 调用nmap执行 -O 扫描操作系统 而且需要在terminal输入root密码 *没办法想扫os就需要这个密码
      os = result["scan"][x]['osmatch'][0]['name'] # 从返回值里通过切片提取出操作系统版本
      prin(x+":"+nm[x]["status"]["state"]+'  '+os+"\n")
   return 0

#端口扫描 ip标准输入的值是192.168.1.1 不指定 range 的话，默认是扫他库里常用的 *windows慢macos很快我也不知道为什么 别问 问就是unix下对于网络协议具有良好的支持
def test_file2(ip,start,end):
#测试用   print(ip,start,end)
   prin('--------------------------------------------------\n')
   x = '2                  端口扫描\n'
   prin(x)
   range = start + '-' + end  # 范围
   nm.scan(ip,range,arguments=' --max-retries=0 ')   # 自适应数据类型功能 👌   --max-retries=0 指定端口扫描探针重传的最大次数为0
   for host in nm.all_hosts():
      prin('--------------------------------------------------\n\n')
      prin('Host : %s \n' % (host))
      prin('State : %s\n' % nm[host].state())
      for proto in nm[host].all_protocols():
         prin('\n')
         prin('Protocol : %s\n' % proto)
         lport = sorted(nm[host][proto].keys())
         for port in lport:
               prin('port : %s\tstate : %s\n' % (port, nm[host][proto][port]['state']))
   return 0

#漏洞扫描
def test_file3(ip):
   prin('--------------------------------------------------\n')
   x = '3                  漏洞扫描\n'
   prin(x)
   prin('--------------------------------------------------\n\n')
   nm.scan(ip,arguments='--script=auth,vuln -oN /Users/elpcoin/Desktop/name.txt') #将漏洞扫描结果保存到本地
   count = len(open('/Users/elpcoin/Desktop/name.txt','r').readlines())  #将漏洞扫描的本地结果打印到 printText 组件中
   with open('/Users/elpcoin/Desktop/name.txt', 'r') as f:
      for line in islice(f.readlines(), 1, count-1):
         prin(line)
   return 0

#GUI基本设置
master = Tk()
master.geometry("356x560")
master.title("端口扫描程序")

#label组件设置
Label(master, text="目的主机IP地址").grid(row=0)
Label(master, text="起始端口").grid(row=1)
Label(master, text="结束端口").grid(row=2)

#输入框
entry1 = tk.StringVar()
entry2 = tk.StringVar()
entry3 = tk.StringVar()
Dst_IP = Entry(master,textvariable=entry1) # 目的主机IP地址
Start_Port = Entry(master,textvariable=entry2) # 起始端口
End_Port = Entry(master,textvariable=entry3) # 结束端口
# 测试用
# Dst_IP.get()
# Start_port.get()
# Start_port.get()

#执行button
print_test = StringVar()
print_test.set('hello')
Button(master, text='主机扫描', command=lambda:test_file1(ip=Dst_IP.get())).grid(row=3, column=0, sticky=W, pady=4)
Button(master, text='端口扫描', command=lambda:test_file2(ip=Dst_IP.get(),start=Start_Port.get(),end=End_Port.get())).grid(row=3, column=1, sticky=W, pady=4)
Button(master, text='漏洞扫描', command=lambda:test_file3(ip=Dst_IP.get())).grid(row=4, column=0, sticky=W, pady=4)
Button(master, text='退出', command=master.quit).grid(row=4, column=1, sticky=W, pady=4) # 退出

#调整输入框
printText = tk.Text(master,width=50,height=30)
printText.insert(INSERT,"扫描结果：\n")
printText.grid(row=5,columnspan=2) # 结果展示框

#显示界面
Start_Port.grid(row=1, column=1)
Dst_IP.grid(row=0, column=1) 
End_Port.grid(row=2, column=1)
master.mainloop( )