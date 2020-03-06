import argparse
import socketserver
import struct
import time


class DNSpackage():
    def __init__(self, data):
        self.headerReader(data[:12]) #解析头
        self.nextData = data[12:]
        self.data = data
        
        for l in range(self.QDCount):
            self.queryReader(self.nextData)

        for l in range(self.ANCount):
            self.answerReader(self.nextData)

    def headerReader(self, headerData):
        self.id, self.flags, self.QDCount, self.ANCount, self.NSCount, self.ARCount = struct.unpack('>HHHHHH', headerData) #处理12字节报头
        
        if(debug >= 2):
            self.printHeaderData()
            
        
    def queryReader(self, queryData):
        self.QName = ''
        i = 0

        tmpData = queryData
        while True:
            d = tmpData[i]
            if d == 0:
                self.QName = self.QName[1:]
                break
            elif d >= 0xC0:
                #指针类型
                d = int.from_bytes(tmpData[i:i+2], byteorder = 'big') - 0xC000
                self.QName += '.'
                self.QName += self.nameFrom(d)
                self.QName = self.QName[1:]
                i += 1
                break

            elif d < 32:
                self.QName += '.'
            else:
                self.QName += chr(d)
            i += 1

        self.QType, self.QClass = struct.unpack('>HH', queryData[i+1:i+5])
        self.queryBytes = queryData[:i+5]
        
        #保存下一段数据
        self.nextData = queryData[i+5:]    
        
        if(debug >= 2):
            self.printQueryData()


    def answerReader(self, answerData):
        self.RName = ''
        i = 0
        while True:
            d = answerData[i]
            if d == 0:
                self.RName = self.RName[1:]
                break
            elif d >= 0xC0:
                #指针类型
                d = int.from_bytes(answerData[i:i+2], byteorder = 'big') - 0xC000
                self.RName += '.'
                self.RName += self.nameFrom(d)
                self.RName = self.RName[1:]
                i += 1
                break
            elif d < 32:
                self.RName += '.'
            else:
                self.RName += chr(d)
            i += 1
        self.RType, self.RClass, self.ttl, self.RDLength = struct.unpack('>HHLH', answerData[i+1:i+11])
        
        #RData以字符串形式赋值
        self.RData = ''
        i += 11 #跳到RData开始位置
        
        #保存下一段数据
        self.nextData = answerData[i+self.RDLength:] 
        
        if self.RType == 1:
            #A记录
            for l in range(0, self.RDLength):
                self.RData += str(answerData[i+l])
                self.RData += '.'
            self.RData = self.RData[:-1]
        
        elif self.RType == 5:
            #CNAME
            tmpData = answerData[i:]
            i = 0
            while True:
                d = tmpData[i]
                if d == 0:
                    self.RData = self.RData[1:]
                    break
                elif d >= 0xC0:
                    #指针类型
                    d = int.from_bytes(tmpData[i:i+2], byteorder = 'big') - 0xC000
                    self.RData += '.'
                    self.RData += self.nameFrom(d)
                    self.RData = self.RData[1:]
                    break
                elif d < 32:
                    self.RData += '.'
                else:
                    self.RData += chr(d)
                i += 1
       
        if(debug >= 2):
            self.printAnswerData()

    
    def nameFrom(self, index):
        i = index
        tmpName = ''
        while True:
            d = self.data[i]
            if d == 0:
                return tmpName[1:]
            elif d >= 0xC0:
                #指针类型
                d = int.from_bytes(self.data[i:i+2], byteorder = 'big') - 0xC000
                tmpName += '.'
                tmpName += self.nameFrom(d)
                return tmpName[1:]
            elif d < 32:
                tmpName += '.'
            else:
                tmpName += chr(d)
            i += 1


    def AAnswer(self, ip):
        self.RName = 49164  #C00C, QName的偏移量
        self.RType = 1
        self.RClass = 1
        self.ttl = 190
        self.RDLength = 4
        self.RData = ip
        self.ANCount = 1
        self.flags = 33152

        if self.RData == '0.0.0.0':
            self.flags = 33155 #No such name
            self.ANCount = 0

        res = struct.pack('>HHHHHH', self.id, self.flags, self.QDCount, self.ANCount, self.NSCount, self.ARCount)    
        res += self.queryBytes
        
        if self.RData != '0.0.0.0':
            item = self.RData.split('.')
            res += struct.pack('>HHHLHBBBB', self.RName, self.RType, self.RClass, self.ttl, self.RDLength, int(item[0]), int(item[1]), int(item[2]), int(item[3]))
        return res

    def CNameAnswer(self, cname):
        self.RName = 49164  #C00C, QName的偏移量
        self.RType = 5
        self.RClass = 1
        self.ttl = 190
        self.RDLength = len(cname) + 2 
        self.RData = cname
        self.ANCount = 1
        self.flags = 33152

        item = self.RData.split('.')
        res = struct.pack('>HHHHHH', self.id, self.flags, self.QDCount, self.ANCount, self.NSCount, self.ARCount)
        res += self.queryBytes
        res += struct.pack('>HHHLH', self.RName, self.RType, self.RClass, self.ttl, self.RDLength)
        for i in item:
            res += len(i).to_bytes(1, byteorder = 'big')
            res += i.encode('gbk')
        i = 0
        res += i.to_bytes(1, byteorder = 'big')
        return res

    def printHeaderData(self):
        #输出Header部分
        print('ID:', self.id)
        print('FLAGS:', self.flags)
        print('QDCOUNT:', self.QDCount)
        print('ANCOUNT:', self.ANCount)
        print('NSCOUNT:', self.NSCount)
        print('ARCOUNT:', self.ARCount)

    def printQueryData(self):
        #输出Query部分
        print('>-Queries---------')
        print('  QNAME:', self.QName)
        print('  QTYPE:', self.QType)
        print('  QCLASS:', self.QClass)

    def printAnswerData(self):
        #输出Answers部分
        print('>-Answers---------')
        print('  RNAME:', self.RName)
        print('  RTYPE:', self.RType)
        print('  RCLASS:', self.RClass)
        print('  TTL:', self.ttl)
        print('  RDLength:', self.RDLength)
        print('  RData:', self.RData)


class myHandler(socketserver.BaseRequestHandler):

    def handle(self):
        if debug >= 1:
            print('\n=================================')
            print(time.asctime(time.localtime(time.time())))
            print(self.client_address)
          
        data = self.request[0]
        info = DNSpackage(data)
        if debug == 1:
            print('asking:', info.QName)
        
        self.socket = self.request[1]
        
        if info.flags >= 32768:
            #32768表示QR位=1，应答报文直接转发
            self.relay2client(data)

        elif info.QType == 1: 
            #A records
            name = info.QName
            if name in DNSdict and DNSdict.get(name)[0] == 'A':
                #本地有记录
                if debug >= 2:
                    print('found: ', name, DNSdict[name])                
                
                ip = DNSdict[name][1]
                self.socket.sendto(info.AAnswer(ip), self.client_address)
            else:
                #本地没有记录
                if debug >= 2:
                    print('not found: ', name)
                self.relay2server(data)
    
        elif info.QType == 5: 
            #CNAME
            name = info.QName
            if name in DNSdict and DNSdict.get(name)[0] == 'CNAME':
                #本地有记录
                if debug >= 2:
                    print('found: ', name, DNSdict[name])                
                
                cname = DNSdict[name][1]
                self.socket.sendto(info.CNameAnswer(cname), self.client_address)
            else:
                #本地没有记录
                if debug >= 2:
                    print('not found: ', name)
                self.relay2server(data)

        else:
            self.relay2server(data)
    
    
    def relay2server(self, data): 
        if(debug >= 2):
            print('asking', NAMESERVER)
        global nextID   
        
        newID = nextID % 1024  #max=65536
        nextID = newID + 1
        orgID = (struct.unpack('>H', data[:2]))[0]

        #记录ID转换
        IDdict[newID] = orgID, self.client_address, time.time()
        newData = struct.pack('>H', newID)
        newData += data[2:]
        self.socket.sendto(newData, (NAMESERVER, PORT))

    def relay2client(self, data):
        
        newID = (struct.unpack('>H', data[:2]))[0]
        if newID in IDdict:
            orgID, clientAddr, recvTime = IDdict.pop(newID)
            
            if time.time() - recvTime >= EXPIREDTIME:
                #超时的返回包，丢弃
                if debug >= 1:
                    print('expried package')
                return 

            newData = struct.pack('>H', orgID)
            newData += data[2:]
            self.socket.sendto(newData, clientAddr)
            if(debug >= 2):
                print('relaying to client', clientAddr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNSRelay Server V2.10.1')
    parser.add_argument('-d', dest='debug', default='0', choices=['0', '1', '2'], help='debug level')
    parser.add_argument('-s', dest='server', default='1.2.4.8', help='dns server ipaddr')
    parser.add_argument('-f', dest='filename', default='dnsrelay.csv', help='file name')
    args = parser.parse_args()
    
    nextID = 0
    debug = int(args.debug)
    NAMESERVER = args.server
    FILENAME = args.filename
    EXPIREDTIME = 2
    HOST = '0.0.0.0'
    PORT = 53
    
    DNSdict = {
        #DNS记录表
        # 域名 -- （记录类型， IP）
    }

    IDdict={
        #id转换字典
        # 转发服务器ID -- （客户端请求ID， 客户端地址， 生成时间）
    }    

    with open(FILENAME) as fdb:
        for record in fdb.readlines():
            item = record.rstrip().split(',')
            DNSdict[item[0]] = (item[1], item[2])
    
    s = socketserver.UDPServer((HOST, PORT), myHandler)
    print('DNS Server Start... ', HOST, PORT)
    print('debug level: ', debug)
    s.serve_forever()
