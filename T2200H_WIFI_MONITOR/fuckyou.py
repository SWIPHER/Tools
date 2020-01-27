import time
import requests
import re
import os
url="http://192.168.1.254"
url_home="http://192.168.1.254/index.html"
loginurl=url+"/login.cgi"
logouturl=url+"/logout.cgi"
session = requests.Session()
def get_sessionKey():
    response = session.get(url_home)
    index_html=response.text
    sessionKey=re.findall("var sessionKey = '(.*?)';",index_html)[0]
    return sessionKey
def login():
    print("[*]Login...!")
    sessionKey=get_sessionKey()
    """Change to your password there"""
    login_data={"inputUserName":"admin","inputPassword":"123456","sessionKey":sessionKey}
    response = session.post(loginurl,data=login_data)
    cookie=session.cookies.get_dict()
    if "err" in response.text:
        print("[*]Wrong Username/Password...!")
        os._exit(0)
    else:
        print("[*]Login success!")
    print("[*]status_code:",response.status_code)
def block(MAC):
    print("[*]Blocking...!")
    sessionKey=get_sessionKey()
    block_url="http://192.168.1.254/wirelesssetup_wirelessmacauthentication.wl"
    block_data={"wlSsid_wl0v0":"TELUS1773","wlFltMacMode_wl0v0":"deny","wlFltMacAddr_wl0v0":MAC,"action":"add","wlSsidIdx":"0","wlSyncNvram":"1","sessionKey":sessionKey}
    response = session.post(block_url,data=block_data)
    if not response.text:
        print("[*]Blcok Success!")
    else:
        print("[*]Block Failed...!")
        os._exit(0)
    print("[*]status_code:",response.status_code)
def unblock():
    print("[*]Unblocking...!")
    unblock_url="http://192.168.1.254/wirelesssetup_wirelessmacauthentication.wl"
    sessionKey=get_sessionKey()
    unblock_data={"wlSsid_wl0v0":"TELUS1773","wlFltMacMode_wl0v0":"disabled","wlFltMacAddr_wl0v0":"","wlSyncNvram":"1","sessionKey":sessionKey}
    response = session.post(unblock_url,data=unblock_data)
    if not response.text:
        print("[*]Unblcok Success!")
    else:
        print("[*]Unblock Failed...!")
        os._exit(0)
    print("[*]status_code:",response.status_code)
def logout():
    print("[*]Logout...!")
    sessionKey=get_sessionKey()
    logout_data={"sessionKey":sessionKey}
    response = session.post(logouturl,data=logout_data)
sessionKey=login()
while(1):
    time.sleep(120)
    block("CC:C0:79:52:7B:52")
    unblock()
