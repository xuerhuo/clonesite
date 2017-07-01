# -*- coding: utf-8 -*-
import socket, sys, thread
import logging, logging.handlers
import SocketServer;
import BaseHTTPServer;
import StringIO,gzip;
import re,os;

BACKLOG = 30;  # set quantities of pending connections
DEBUG_INFO = True;  # set to True to see the debug msgs
MAX_BUFFER_SIZE = 4096;  # set the max amount of data to be received at once
LOG_FILE = "test.log";
LISTEN_PORT = 1080;
LISTEN_HOST= 'www.hglaser.com';
SAVE_DIR=r'D:/temp';

# LOG_FILE_SEND="testSend.log"

def logInfo(msg):
    return 1;
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=5);  # 实例化handler
    fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(name)s - %(message)s';
    formatter = logging.Formatter(fmt);  # 实例化formatter
    handler.setFormatter(formatter);  # 为handler添加formatter

    logger = logging.getLogger('tst');  # 获取名为tst的logger
    logger.addHandler(handler);  # 为logger添加handler
    logger.setLevel(logging.DEBUG);
    logger.info(msg);


def initBind(argvs):
    host = '';

    if (len(argvs) < 2):
        print "no port given,using port :",LISTEN_PORT
        port = LISTEN_PORT;
    else:
        port = sys.argv[1];

    print 'proxy server running on', host, ':', port;

    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        soc.bind((host, port));
        soc.listen(BACKLOG);
    except socket.error, (value, msg):
        if soc:
            soc.close();
        print "could not open socket:", msg
        sys.exit(1);

    while 1:
        conn, client_addr = soc.accept();
        thread.start_new_thread(proxyThread, (conn, client_addr));
        #print "address is ", client_addr;


def proxyThread(conn, client_addr):
    request = '';
    host='';
    while True:
        tmpRequest = conn.recv(MAX_BUFFER_SIZE);
        request += tmpRequest;
        if len(tmpRequest) < MAX_BUFFER_SIZE:
            break;
    #print "recv request from browser has finished\n";
    logInfo(request);
    try:
        host = request.split('\n')[1].split(':')[1].strip();
        log_msg = "host is ", host;
    except Exception:
        pass;

    try:
        getfile=re.findall(r"[GET|get|post|POST] http://"+LISTEN_HOST+"([a-zA-Z0-9/\._-]*)",request);
    except:
        exit(1)
    if(LISTEN_HOST==host):
        #print log_msg
        getfile=getfile[0].replace('\\','/')
        print getfile,'\n'
    else:
        pass
    #logInfo(log_msg);
    try:
        connServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        connServer.connect((host, 80));
        connServer.send(request);
        temp='';
        while True:
            data = connServer.recv(MAX_BUFFER_SIZE);
            if len(data) > 0:
                conn.send(data);
                temp+=data;
            else:
                break;
        if (LISTEN_HOST == host):
            try:
                bodylen=long(re.findall(r"Content-Length: (\d*)",temp)[0])
            except:
                print temp;
            body=temp[len(temp)-bodylen:];
            body=readgzip(body);
            svae_file_i(SAVE_DIR+getfile,body);
        connServer.close();
        conn.close();

    except socket.error, (value, msg):
        if connServer:
            connServer.close;
        if conn:
            conn.close;
        print msg;
        sys.exit(1);

def svae_file_i(path,content):
    dir=os.path.split(path);
    print dir;
    print os.path.exists(dir[0]);
    if os.path.exists(dir[0]):
        pass
    else:
        os.makedirs(dir[0]);
    fh = open(path, 'wb')
    fh.write(content)
    fh.close()
def readgzip(content):
    compresseddata = content;
    compressedstream = StringIO.StringIO(compresseddata)
    gzipper = gzip.GzipFile(fileobj=compressedstream)
    try:
        data = gzipper.read();
    except:
        data=content;
    return data;
class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """docstring for LocalProxyHandler"""
    '''def __init__(self, arg=None):
        super(LocalProxyHandler, self).__init__()
        self.arg = arg
    '''

    def do_GET(self):
        print self.headers;
        print 'hello world'

    def do_POST(self):
        return self.do_GET();


class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    """docstring for LocalProxyServer"""
    daemon_threads = True;


def main():
    '''server_address=('',LISTEN_PORT);
    httpd=LocalProxyServer(server_address,LocalProxyHandler);

    print 'proxy server running......'
    httpd.serve_forever();'''
    initBind(sys.argv);


if __name__ == '__main__':
    main();