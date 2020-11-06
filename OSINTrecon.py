try:
    import requests
    import dns.resolver
    # import fofa  fofa模块出了问题，可能不能使用其api。
    import colorama  # 颜色模块
    import shodan


except ImportError:
    import os

    os.system('pip3 install shodan')
    os.system('pip3 install requests')
    os.system('pip3 install dnspython')
    os.system('pip3 install colorama')

from http import cookiejar
import re
import os
import configparser
import json
import random

G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
R = '\033[91m'
W = '\033[0m'

'''
脚本运行主要逻辑：
当：osint_obj = OSINTrecon(domain="domain.com")时【即用户指定的是域名】，可以调用以下方法：
osint_ojb.ip2domain（） 、 osint_obj.zoomeye_recon() 、osint_obj.shodan_uav（）、osint_obj.google_uav（）
osint_obj = OSINTrecon(ip="11.45.1.4")时【即用户指定的是ip地址】，可以调用以下方法：
osint_ojb.ip2domain（） 、 osint_obj.zoomeye_recon() 、osint_obj.shodan_uav（）

【重要的指示】：Zoomeye和shodan的token都通过config.ini来指定
'''


class OSINTrecon():
    def __init__(self, domain=None, ip=None):
        self.domain = domain
        self.subdomain = set()  # 子域名
        self.ip2domains = set()  # 旁站域名的集合。
        self.ip = ip
        self.UA_length = 0

    def get_dns_a_record(self):
        ip = []
        a_record = dns.resolver.resolve(self.domain, 'A')
        for i in range(1, len(a_record.response.answer)):
            for j in a_record.response.answer[i]:
                ip.append(j.to_text().split()[-1])
        return ip

    '''
    返回的数据：
    无论查询成功与否，都会返回一个集合，这个集合里边包含了可能有的目标的旁域。

    '''

    def ip2domain(self):
        ip = []
        if self.ip is None:  # 当用户指定了域名而非ip的时候，先对域名进行dns解析得到ip地址，然后再用此ip地址来进行旁站查询。
            ip = self.get_dns_a_record()
        else:  # 当有ip传进来的时候
            ip.append(self.ip)
        for i in ip:
            cookie = cookiejar.CookieJar()
            url = 'https://site.ip138.com/{ip}/'.format(ip=i)
            headers = {
                'User-Agent': 'Mozilla/5.0(Windows NT 10.0; WOW64)AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/53.0.2785.104 Safari/537.36 Core/1.53.3427.400 QQBrowser/9.6.12513.400 '
            }
            try:
                resp = requests.get(url, headers=headers, cookies=cookie, timeout=10)
                if resp.status_code != 200:
                    # print("red + [!]查询次数过多,查询失败")
                    # Style.RESET_ALL
                    return self.ip2domains
                pattern = r'<li><span class="date">(.*?)target="_blank">(.*?)</a></li>'
                matches = re.finditer(pattern, resp.text)
                for match in matches:
                    self.ip2domains.add(match.group(2))  # 集合去重
                return self.ip2domains
                # print(resp.text)
            except:
                # print(red+'[!]查询失败')
                # Style.RESET_ALL
                return self.ip2domains

    '''
    进行的功能：
    使用命令行进行shodan查询。只进行是否是蜜罐的查询
    返回的东西：
    无论是运行成功还是运行错误，都会返回字符串。（带有颜色）
    '''

    def shodan_uav(self):  # 使用shodan来识别对方是否是蜜罐。（识别对象：ip）
        ip = []
        reverse_str = ''
        if self.ip is None:  # 当用户指定了域名而非ip的时候，先对域名进行dns解析得到ip地址，然后再用此ip地址来进行旁站查询。
            ip = self.get_dns_a_record()
        else:  # 当有ip传进来的时候
            ip.append(self.ip)
        try:
            config = configparser.ConfigParser()
            config.read('config.ini')
            shodan_api = config['Shodan API']['shodan_api']
            # shodan_api = input('[请输入shodan API]>>')
            # print(shodan_api)
            """if len(ip)>=2:
                flag = input(Y+"当前要进行查询的ip有{num}个，可能较多消耗shodan查询次数，是否继续？Y/n".format(num=len(ip)))
                if flag =="Y":
                    pass
                else:
                    return 100 #user quit"""
            for i in ip:
                os.system('shodan init {api_key}'.format(api_key=shodan_api))
                honeyscore_result = os.popen('shodan honeyscore {ip}'.format(ip=i)).read()
                reverse_str += "for IP {ip}:\n".format(ip=i)
                if 'Error' in honeyscore_result:
                    reverse_str += R
                    reverse_str += honeyscore_result
                elif "Not a honeypot" in honeyscore_result:
                    reverse_str += G
                    reverse_str += honeyscore_result
                else:
                    reverse_str += Y
                    reverse_str += honeyscore_result
        except:
            reverse_str += "config 文件出错"

        return reverse_str

    '''
    专门对host search的结果进行提取和整理。
    负责：
        1、提取hostSearch API返回的结果（部分）
        2、在ssl证书当中查找旁域
    
    '''

    def zoomeye_host_search_info_graping(self, target_data):
        dict = {}
        for i in target_data['matches']:
            target = '{ip}:{portnum}'.format(ip=i['ip'], portnum=i['portinfo']['port'])
            dict[target] = {}
            dict[target]['port_num'] = i['portinfo']['port']
            dict[target]['os'] = i['portinfo']['os']
            dict[target]['device'] = i['portinfo']['device']
            dict[target]['application'] = i['portinfo']['app']
            banner = i['portinfo']['banner']
            try:
                script_type = r'(?s)(?i)jsp|php|asp'
                dict[target]['script_type'] = re.search(script_type, banner).group()
            except:
                dict[target]['script_type'] = ''
            try:
                certificate_pattern = 'SSL Certificate'
                ssl_banner = banner[re.search(certificate_pattern, banner).start():]
                dns_domain = re.search(r'DNS:(.*)', ssl_banner).group(1).split(', DNS:')
                for j in dns_domain:
                    self.ip2domains.add(j)
            except:
                pass
        return dict

    def zoomeye_web_search_info_graping(self, target_data):
        dict = {}
        for i in target_data['matches']:
            site = i['site']
            self.subdomain.add(site)
            dict[site] = {}
            dict[site]['site_ip'] = i['ip']
            dict[site]['waf'] = i['waf']
            dict[site]['system'] = i['system']
            dict[site]['database'] = i['db']
            dict[site]['component'] = i['component']
            dict[site]['framework'] = i['framework']
            dict[site]['webapp'] = i['webapp']
            dict[site]['headers'] = i['headers']
            dict[site]['server'] = i['server']
        return dict

    '''
    进行zoomeye中的信息侦察（主要是获取host信息、ssl证书、目标可能存在的漏洞等等）【因此这个模块还需要更多的完善】
    返回信息：一个列表，两样东西：[<状态>,<zoomeye中搜集到的信息（target_info，一个字典）>]
    当用户指定了ip地址的时候，进行host search；当用户指定了域名的时候，进行web search
    字典内容如（进行web search时）：
    {'demo.testfire.net':{'site_ip':['65.61.137.117'],'waf':[]:'component':[],'system':[],'db':[],'header':'','framework':[],'webapp':''}}
    又如（进行host search）：
    {'65.61.137.117:8080': {'port_num': 8080, 'os': '', 'device': '', 'application': 'Apache httpd'}, '65.61.137.117:443': {'port_num': 443, 'os': '', 'device': '', 'application': 'Apache httpd'}
    
    当请求出错的时候，<状态>就会显示出错的缘由（字符串类型），<信息>就是None。
    '''

    def zoomeye_recon(self):  # zoomeye搜索。zoomeye目前是负责进行目标漏洞的获取。该模块还未经详细的测试
        reverse_info = []  # 汇总信息的一个列表
        search_stats = ''  # 请求的状态（当出错的时候用）
        url = 'https://api.zoomeye.org/user/login'
        result = {}
        zoomeye_config = configparser.ConfigParser()
        zoomeye_config.read('config.ini')
        result['username'] = zoomeye_config['ZoomEye Login']['username']
        result['passwd'] = zoomeye_config['ZoomEye Login']['passwd']
        login_data = json.dumps({'username': result['username'],
                                 'password': result['passwd']})
        try:
            resp = requests.post(url, data=login_data, timeout=10)
        except:
            search_stats += '进行Zoomeye认证时请求超时'
            target_info = None
            reverse_info.append(search_stats)
            reverse_info.append(target_info)
            return reverse_info
        if resp.status_code == 200:  # 登录认证成功
            resp = resp.json()
            access_token = resp['access_token']
            header = {'Authorization': 'JWT {access_token}'.format(access_token=access_token)}
            params = {'query': self.domain if self.domain else self.ip}
            web_search_API = 'https://api.zoomeye.org/web/search'
            host_search_API = 'https://api.zoomeye.org/host/search'
            API_use = web_search_API if self.domain else host_search_API

            try:
                resp = requests.get(API_use, params=params, headers=header, timeout=10)
                if resp.status_code != 200:
                    search_stats += '登录认证成功，但搜索请求被拒绝，可能是API出了问题'
                    target_info = None
                    reverse_info.append(search_stats)
                    reverse_info.append(target_info)
                    return reverse_info
                target_data = json.loads(resp.text)  # json.loads()用于将str转换成dict类型。
                if self.ip:  # 使用host search时

                    target_info = self.zoomeye_host_search_info_graping(target_data)  # target_info是一个字典
                    search_stats += 'IP搜索请求成功'
                    reverse_info.append(search_stats)
                    reverse_info.append(target_info)
                    return reverse_info
                else:  # 调用了web_search方法

                    target_info = self.zoomeye_web_search_info_graping(target_data)
                    search_stats += 'IP搜索请求成功'
                    reverse_info.append(search_stats)
                    reverse_info.append(target_info)
                    return reverse_info

            except:
                search_stats += '进行zoomeye搜索过程中请求超时，可能是网络或者zoomeye服务器出了问题'
                target_info = None
                reverse_info.append(search_stats)
                reverse_info.append(target_info)
                return reverse_info

        else:
            search_stats += 'Zoomeye登录失败，检查config中参数指定情况'
            target_info = None
            reverse_info.append(search_stats)
            reverse_info.append(target_info)
            return reverse_info

    def fofa_recon(self):  # 进行fofa API 查询（马上氪钱！！）
        pass

    '''
    从http://useragentstring.com/pages/useragentstring.php?name=All中随机获取一个开头为‘mozila’的UA
    这个函数应当是在init的时候用，给本地写入一个全部UA的字典。后边启动就快多了
    '''

    def UA_init(self):
        cookie = cookiejar.CookieJar()
        url = 'http://useragentstring.com/pages/useragentstring.php?name=All'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                 'Chrome/84.0.4147.125 Safari/537.36'}
        try:
            resp = requests.get(url, headers=headers, cookies=cookie, timeout=10)
            if resp.status_code == 200:
                UA_pattern = r'>(Mozilla[^<]*?)</a></li>'  # 要加if语句判定状态码
                self.UA_length = len(re.findall(UA_pattern, resp.text))
                User_Agents = re.findall(UA_pattern, resp.text)
                ua_file = open('UA_lib.txt', 'w+')
                for User_agent in User_Agents:
                    ua_file.write('\n' + User_agent)
                ua_file.close()
                print('UA init Success!')
                return 1
            else:
                print('UA init was abort by remote services')
                return 0
        except:
            print('UA init timeout')
            return 0

    '''
    检索UA_file是否存在，如果不存在，则获取UA file，如果获取UAfile不成功，则使用较小的UA字典并从中随机挑选一个UA。
    '''

    def get_fake_UA(self):
        if os.path.exists('UA_lib.txt'):
            pass
        else:
            self.UA_init()
        if not os.path.exists('UA_lib.txt'):
            ua_lib = ['Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, '
                      'like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19',
                      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36',
                      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36',
                      'Mozilla/5.0 (PlayBook; U; RIM Tablet OS 2.1.0; en-US) AppleWebKit/536.2+ (KHTML, like Gecko) Version/7.2.1.0 Safari/536.2+',
                      'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
                      'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27'
                      'Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3'
                      'Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3'
                      'Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3',
                      'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36',
                      ]
            self.UA_length = len(ua_lib)
            choice = random.randint(0, self.UA_length)
            user_agent = ua_lib[choice]
            headers = {'User-Agent': user_agent}
            return headers
        ua_lib = open('UA_lib.txt', 'r').read()
        ua_lib = ua_lib.split('\n')
        self.UA_length = len(ua_lib)
        choice = random.randint(0, self.UA_length)
        user_agent = ua_lib[choice]
        headers = {'User-Agent': user_agent}
        return headers

    '''
    小函数，专门对从google爬取到的subdomains进行清理,因为正则的初步筛选得到的结果可能带有一点冗杂数据
    subdomains是一个列表
    '''

    def clean_subdomain_data(self, subdomains):
        for i in range(len(subdomains)):
            space_index = subdomains[i].find(' ')
            subdomains[i] = subdomains[i][:space_index]
        sub_domains = set(subdomains)
        return sub_domains

    '''
    进行基于google的子域名查询
    
    函数运行原理：从User-Agent集合网站中获取一个随机的User-Agent作为请求的header，将（用户输入的）域名作为搜索的内容，进行搜索。
    为了使得子域名搜集范围尽可能的广，方法进行了两次查询。查询规则如：当查询的域名为“testfire.net”时，第一次查询的关键字：site:testfire.net
    查询出“evil.testfire.net”,"demo.testfire.net",'demo2.testfire.net',于是，第二次查询关键字如：
    site:testfire.net -demo -evil -demo2 -<最多减7个子域>
    
    注意事项：
    0、仅当用户输入了域名的时候该方法才有用
    1、返回目标子域名的集合（可能是空集）；当返回值为None的时候，说明header信息可能有问题，重新运行一次（运气不好就需要多次）该方法就可能得到子域名集合（强烈建议在sleep一段时间之后再运行）。
    2、由于仅进行了两次google内容爬取，因此没有使用google域名轮询技术。
    3、第二次进行google查询时，使用的UA跟第一次的相同
    4、请勿多次运行该方法（不可连续运行30次），以防止google封ip
    '''

    def google_uav(self):
        cookie = cookiejar.CookieJar()
        reverse_info = []
        url = 'https://google.com/search?hl=zh-CN&q={query}&btnG=Search&gbv=1&num=100'
        headers = self.get_fake_UA()
        resp = requests.get(url.format(query='site:' + self.domain), headers=headers, cookies=cookie,
                            timeout=10)
        link_pattern = '(?s)(?i)([^>]*?)› [\w]*?</div>'  # 由于google返回页面中链接全部都在<div>标签当中，因此使用pyquery的话就很难区分开。此时使用正则是最为高效的方案
        sub_domains = re.findall(link_pattern, resp.text)
        self.sub_domains = self.clean_subdomain_data(sub_domains)
        sub_string = list(self.sub_domains)
        # print(sub_string)
        for i in range(len(sub_string)):
            p_index = sub_string[i].find('.')
            sub_string[i] = sub_string[i][:p_index]
        # print(sub_string)

        query_string = 'site:' + self.domain
        try:
            for i in range(7):
                query_string += ' -'
                query_string += sub_string[i]
            # print(query_string)
            resp = requests.get(url.format(query=query_string), headers=headers, cookies=cookie,
                                timeout=10)
            link_pattern = '(?s)(?i)([^>]*?)› [\w]*?</div>'
            sub_domains = re.findall(link_pattern, resp.text)
            sub_domains_set = self.clean_subdomain_data(sub_domains)
            for i in sub_domains_set:
                self.sub_domains.add(i)

            return self.sub_domains
        except:  # 无效的header，建议重来。
            # print(resp.text)
            # print('header无效')
            return None


if __name__ == "__main__":
    uav = OSINTrecon(domain='testfire.net')
    # print(uav.ip2domain())
    # print(uav.shodan_uav())测试成功
    # print('这是搜索结果', uav.zoomeye_recon())
    # print('旁域：',uav.ip2domains)测试成功
    # print(uav.get_fake_UA())
    print(uav.google_uav())  # 测试成功
