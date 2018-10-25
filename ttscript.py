#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#--------------------#
import string
from random import *
import time
import socket
import os
import requests
from colored import fg, bg
import threading
import whois
import sys
from proxybroker import Broker
import asyncio
#---------------------#

#---------------------#
red = (fg(1))
white = (fg(15))
green = (fg(40))
end = '\033[0m'
yellow = '\33[93m'
cdcolor = (fg(63))
#---------------------#



#portscan

def nmapAPI():
    os.system("clear")
    print("""
██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""")
    ip = input("Enter ip: ")
    r = requests.get("https://api.hackertarget.com/nmap/?q={}". format(ip))
    print(r.text)

#-------------------------

def portscanner():
    os.system("clear")
    print("""
██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = input("Enter ip: ")
    prt = int(input("Enter port: "))
    def pscan(port):
        try:
            con = s.connect((ip,port))
            return True
        except:
            return False

    for x in range(prt+1):
        if pscan(x):
            print("Port",x,"is open")

#-----------------------------------------#
            
#ipscan
def ipscan():
    os.system("clear")
    print("""
██╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██║██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""")
    ip0=input('starting ip : ')
    ip1=input('ending ip : ')
    port=int(input('port number : '))
    timeout=int(input('timeout :'))
    timeout=timeout/1000
    print()
    ip0=list(map(int,ip0.split(".")))
    ip01=list(map(int,ip1.split(".")))
    class IpAddr:
        def __init__(self,d,c,b,a):
            self.a=a
            self.b=b
            self.c=c
            self.d=d
        def increase(self):
            self.a+=1
            if self.a>255:
                self.a=0
                self.b+=1
            if self.b>255:
                self.b=0
                self.c+=1
            if self.c>255:
                self.c=0
                self.d+=1
            return str(self.d)+"."+str(self.c)+"."+str(self.b)+"."+str(self.a)
        def data(self):
            return str(self.d)+"."+str(self.c)+"."+str(self.b)+"."+str(self.a)
        def next(self):
            self.b+=1
            if self.b>255:
                self.b=0
                self.c+=1
            if self.c>255:
                self.c=0
                self.d+=1
            return str(self.d)+"."+str(self.c)+"."+str(self.b)+"."+str(self.a)
        def diff(self,x,y,z,w):
            return (x-self.d)*256**2+(y-self.c)*256+z-self.b
    def find(z,i):
        i=list(map(int,i.split(".")))
        ip=IpAddr(i[0],i[1],i[2],i[3])
        global cnt
        while i!=z:
           i=ip.data()
           s=socket.socket()
           s.settimeout(timeout)
           try:
               s.connect((i,port))
               print(i)
               cnt+=1
           except:
               pass
           s.close()
           i=ip.increase()
    ip=IpAddr(ip0[0],ip0[1],ip0[2],ip0[3])
    n=ip.diff(ip01[0],ip01[1],ip01[2],ip01[3])-1
    cnt=0
    d={}
    for i in range(n):
        p,q=ip.data(),ip.next()
        d[i]=threading.Thread(target=lambda:find(q,p))
        d[i].daemon=True
        d[i].start()
    find(ip1,ip.data())

#infoip

def infoIP():
    print("""
██╗██████╗       ██╗███╗   ██╗███████╗ ██████╗ 
██║██╔══██╗      ██║████╗  ██║██╔════╝██╔═══██╗
██║██████╔╝█████╗██║██╔██╗ ██║█████╗  ██║   ██║
██║██╔═══╝ ╚════╝██║██║╚██╗██║██╔══╝  ██║   ██║
██║██║           ██║██║ ╚████║██║     ╚██████╔╝
╚═╝╚═╝           ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ 
""")
    os.system("clear")
    ip = input("Enter ip: ")
    r = requests.get("https://ipapi.co/{}/json/". format(ip))
    infotext = "{}". format(r.json())
    s = infotext.split("'")
    print("--------------------")
    print("""ip: {}
city: {}
region: {}
region code: {}
country: {}
country name:‌{}
continent code: {}
postal: {}
currency: {}
languages: {}
timezone: {}
country calling code: {}
org: {}""". format(s[3],s[7],s[11],s[15],
s[19],s[23],s[27],s[33],s[53],
s[57],s[41],s[49],s[65]))
    print("--------------------")

#whois
def whoiiss():
    os.system("clear")
    print("""
██╗    ██╗██╗  ██╗ ██████╗ ██╗███████╗
██║    ██║██║  ██║██╔═══██╗██║██╔════╝
██║ █╗ ██║███████║██║   ██║██║███████╗
██║███╗██║██╔══██║██║   ██║██║╚════██║
╚███╔███╔╝██║  ██║╚██████╔╝██║███████║
 ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝
""")
    inpdomain = "nabegheha.com"
    domain = whois.query(inpdomain)
    print("""name : {}
registrar: {}
creation date: {}
expiration date: {}
name_servers: {}""". format(domain.name,domain.registrar,
domain.creation_date,domain.expiration_date,domain.name_servers))

#proxy finder

def proxyFINDER():
    os.system("clear")
    print("""
███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
""")
    limitproxy = int(input("limit: "))
    typeproxy = input("types[HTTP(s),SOCKS4/5]: ")
    timeoutproxy = int(input("timeout[SECONDS]: "))
    print("-------------------------------")
    async def show(proxies):
        while True:
            proxy = await proxies.get()
            if proxy is None: break
            print("New Proxy: %s" % proxy)
    proxies = asyncio.Queue()
    broker = Broker(proxies)
    tasks = asyncio.gather(
        broker.find(types=[typeproxy],limit=limitproxy,timeout=timeoutproxy),
        show(proxies))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tasks)
    print("-------------------------------")

#password maker
def passmaker():
    os.system("clear")
    print("""
██████╗ ███╗   ███╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔══██╗████╗ ████║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██████╔╝██╔████╔██║███████║█████╔╝ █████╗  ██████╔╝
██╔═══╝ ██║╚██╔╝██║██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
██║     ██║ ╚═╝ ██║██║  ██║██║  ██╗███████╗██║  ██║
╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
""")
    inplenght = int(input("password lenght: "))
    lenght = string.ascii_letters +  string.digits + string.punctuation + string.hexdigits
    password = "".join(choice(lenght) for i in range(randint(inplenght,inplenght)))
    print("your password: ",password)

#-----------------------------------------#
def menu():
    menu = str(input("""
{0}[99]{1} exit
{2}[100]{3} Back to the main menu
tt@script#~ """ . format(red,end,yellow,end)))
    if (menu == "100"):
        os.system("clear")
        ttscript()
    elif (menu == "99"):
        quit()
    else :
        pass
#----------------------------------------#
Banner = """
████████╗████████╗███████╗ ██████╗██████╗ ██╗██████╗ ████████╗
╚══██╔══╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝
   ██║      ██║   ███████╗██║     ██████╔╝██║██████╔╝   ██║   
   ██║      ██║   ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   
   ██║      ██║   ███████║╚██████╗██║  ██║██║██║        ██║   
   ╚═╝      ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   
        v 1    |    Dr.Cyber    |    githib.com/Dr-Cyb3r      """


menupscan = """
██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""
#------------------------------------------#




def ttscript():
    os.system("clear")
    print(Banner)
    inpmnu = str(input("""{0}[1]{1} password maker
{0}[2]{1} whois
{0}[3]{1} port scanner
{0}[4]{1} ip scanner
{0}[5]{1} proxy finder
{0}[6]{1} ip info
{2}[99]{3} exit
tt@script#~ """. format(yellow , end , red, end)))

    def ifelif():
        if inpmnu == "1":
            passmaker()
            menu()

        elif inpmnu == "2":
            whoiiss()
            menu()

        elif inpmnu == "3":
            os.system("clear")
            print(menupscan)
            scanmode = input("""{0}[1]{1} NMAP SCAN
{0}[2]{1} port scan
{2}[99]{3} exit
tt@script#~ """. format(yellow,end,red,end))
            if scanmode == "1":
                nmapAPI()
                menu()
            elif scanmode == "2":
                portscanner()
                menu()

        elif inpmnu == "4":
            ipscan()
            menu()

        elif inpmnu == "5":
            proxyFINDER()
            menu()
        
        elif inpmnu == "6":
            infoIP()
            menu()
        elif inpmnu ==  "100":
            quit()
        else :
            os.system("clear")
            ttscript()
    ifelif()    
            

ttscript()
