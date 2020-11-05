import nmap


def single_port():
        host = '14.215.177.39'
        port = 80
        num=0
        nm = nmap.PortScanner()
        print("-------------------------------")
        try :
                nm.scan(host, str(port))
                print('Host : %s ' % host)
                print('State : %s' % nm[host].state())
                for proto in nm[host].all_protocols():
                        print('----------')
                        print('Protocol : %s' % proto)
                        lport = list(nm[host][proto].keys())
                        lport.sort()
                        if port in lport:
                                print('port: %s\tstate: %s' % (port,nm[host][proto][port]['state']))
                                num=num+1
                if num==0:
                        print("the port is close")
        except Exception as e:
                print('Scan error:' + str(e))



def port_net():
        host='14.215.177.39'
        start=80
        end=100
        num=0
        try:
                nm=nmap.PortScanner()
                nm.scan(host,  arguments='str(start)-str(end)')
                print("-------------------------------")
                print('Host : %s ' % (host))
                print('State : %s' % (nm[host].state()))
                for proto in nm[host].all_protocols():
                        print('----------')
                        print('Protocol : %s' % proto)
                        lport = list(nm[host][proto].keys())
                        lport.sort()
                        for port in range(start,end):
                                if port in lport:
                                        print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                                        num=num+1
                if num==0:
                        print("no port is open")
        except Exception as e:
                print('Scan error:' + str(e))




def main():
        print("1 means the single port,2 means the net")
        choice=input("input:")
        if(choice=='1'):
                single_port()
        if(choice=='2'):
                port_net()


if __name__ == '__main__':
        main()