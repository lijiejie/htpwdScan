# encoding=utf-8
# An HTTP(s) weak pass scanner v 0.0.1
# my[at]lijiejie.com

import sys
import argparse
import httplib
import urllib
import threading
import Queue
import time
import re
import urlparse
import os
import random


def get_args():
    parser = argparse.ArgumentParser(description='* HTpwdScan is An HTTP/HTTPS weakpass scanner *')
    parser.add_argument('-f', metavar='REQUESTFILE', type=str,
                        help='Load HTTP request from file')
    parser.add_argument('-u', metavar='REQUESTURL', type=str,
                        help='Set request URL')
    parser.add_argument('-m', metavar='METHOD', type=str, default='POST',
                        choices=['POST', 'GET'],
                        help='Set -m=GET only when you use -u and the method is GET, default is POST')
    parser.add_argument('-https', default=False, action='store_true',
                        help='Set -https only when load request from POSTFILE')
    parser.add_argument('-d', metavar='Param=DictFilePath', type=str, nargs='+', required=True,
                        help='set dictionary for each parameter \
                                e.g. user=users.dic pass=pass.dic ')
    parser.add_argument('-t', metavar='THREADS', type=int, default=50,
                        help='default set to 50')
    parser.add_argument('-err', metavar='ERR', default='', type=str,
                        help='String indicates fail in response text')
    parser.add_argument('-suc', metavar='SUC', default='', type=str,
                        help='String indicates success in response text')
    parser.add_argument('-herr', metavar='HERR', default='', type=str,
                        help='String indicates fail in response headers')
    parser.add_argument('-hsuc', metavar='HSUC', default='', type=str,
                        help='String indicates success in response headers')
    parser.add_argument('-proxy', metavar='Server:Port', default='', type=str,
                        help='Set HTTP proxy like 127.0.0.1:8000')
    parser.add_argument('-no302', default=False, action='store_true',
                        help='302 redirect insensitive, default is sensitive')
    parser.add_argument('-fip', default=False, action='store_true',
                        help='Use random fake IPs')
    parser.add_argument('-o', metavar='OUTPUT', type=str, default='Cracked_Pass.txt',
                        help='Output file, defaut is Cracked_Pass.txt')
    parser.add_argument('-nov', default=False, action='store_true',
                        help='Do not print verbose messages, only print cracked ones')
    parser.add_argument('-debug', default=False, action='store_true',
                        help='Print response header and response text')
    if len(sys.argv) == 1:    # show help message when no args
        sys.argv.append('-h')
    return parser.parse_args()

args = get_args()
if os.name == 'nt':
    args.err = args.err.decode('gbk', 'ignore')    # decode gbk first under Windows
    args.suc = args.suc.decode('gbk', 'ignore')
else:
    args.err = args.err.decode('utf-8', 'ignore')   # decode utf-8 under linux
    args.suc = args.suc.decode('utf-8', 'ignore')
if args.f == None and args.u == None:
    raise Exception('Both RequestFILE and RequestURL are missing!\
                    \n' + ' ' * len('Exception: ')  + 'Use -f or -u to set one')
if args.debug:
    args.t = 1    # debug on, thread set to 1
    print '#' * 13, 'DEBUG on, Below is arguments parsed:', '#' * 13
    print args
    print '#' * 64
if len(args.proxy) >= 10 and args.proxy.find(':') > 0:    # Proxy enablded
    pserver, pport = args.proxy.split(':')
    args.proxy_on = True
else:
    args.proxy_on = False

print 'Job started on # %s #' % time.asctime()    
queue = Queue.Queue()    # Parameters queue
selected_params = []
def gen_queue():
    # generate python code, here I will not close files, forgive me...
    str_code = ''
    indent = 0
    for param in args.d:
        pname = param.split('=')[0].strip()    # parameter name
        fname = param.split('=')[1].strip()    # dict file name
        selected_params.append( (pname, fname) )
        str_code += '    ' * indent
        indent += 1
        str_code += "for line" + str(indent) + " in open('" + fname + "', 'r'):\n"
    str_code += '    ' * indent + 'while True:\n'
    indent += 1
    str_code += '    ' * indent + 'if queue.qsize() < args.t:\n'
    indent += 1
    str_code += '    ' * indent
    index = 1
    str_line = ''
    for param in args.d[:-1]:
        str_line += 'line' + str(index) + ".strip() + ' ' + "
        index += 1
    str_line += 'line' + str(index) + '.strip()'
    str_code += "queue.put(" + str_line + ")\n"
    str_code += '    ' * indent + 'break\n'
    str_code += '    ' * (indent - 1) + 'time.sleep(0.001)\n'
    if args.debug:
        for i in range(len(args.d)):
            str_code += '    ' * (indent - 2 - i) + 'break\n'
    str_code += 'for i in range(args.t):\n    queue.put(None)\n'
    if args.debug:
        print '#' * 14, 'DEBUG on, below is generated code', '#' * 15
        print str_code    # uncomment this line to see what str_code is
        print '#' * 64
    exec(str_code)

threading.Thread(target=gen_queue).start()   # put parameters in queue


headers = {}
def parse_request():     
    if args.u != None:    # parse url
        (args.scm, args.netloc, args.path, params, args.query, fragment) = \
                   urlparse.urlparse(args.u, 'http')
    else:    # load request from file
        with open(args.f) as f:
            post_text = f.read()
        if args.https:
            args.scm = 'https'
        else:
            args.scm = 'http'
        lines = post_text.split('\n')
        first_line = lines[0]
        if first_line.find('GET') >= 0:
            args.m = 'GET'
        else:
            args.m = 'POST'
        args.path = first_line.split(' ')[1]
        args.netloc = re.search('Host: (.*)', post_text).group(1)    # host name
        if args.m == 'POST':    # find query data
            for i in range(len(lines) -1 , 0, -1):
                if len(lines[i].strip()) > 0:
                    args.query = lines[i]
                    break
        else:    # deal with GET
            (scm, netloc, args.path, params, args.query, fragment) = urlparse.urlparse(args.path)

        # deal with headers, be careful that do not accecpt encoding-gzip
        try:
            headers['User-Agent'] = re.search('User-Agent: (.*)', post_text).group(1).strip()
        except:
            pass
        try:
            headers['Cookie'] = re.search('Cookie: (.*)', post_text).group(1).strip()
        except:
            pass
        try:
            headers['Origin'] = re.search('Origin: (.*)', post_text).group(1).strip()
        except:
            pass
        try:
            headers['Referer'] = re.search('Referer: (.*)', post_text).group(1).strip()
        except:
            pass
    if args.fip:
        headers['X-Forwarded-For'] = str(random.randint(1,255)) + '.' + \
                                   str(random.randint(1,255)) + '.' + \
                                   str(random.randint(1,255)) + '.' + \
                                   str(random.randint(1,255))
    headers['Cache-Control'] = 'no-cache'
    if args.m == 'POST':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if not args.netloc.find(':') > 0:    # under Linux, netloc must splited
        args.host = args.netloc.strip()
        args.host_port = 80
    else:
        args.host, args.host_port = args.netloc.split(':')
        args.host = args.host.strip()
        args.host_port = int(args.host_port)
        
parse_request()


lock = threading.Lock()
def do_request():
    while True:
        params = queue.get()
        if params == None:
            queue.task_done()
            return
        else:
            params = params.split(' ')
        data = args.query
        index = 0
        for p in selected_params:    # replace param value
            if data.find(p[0] + '=') >= 0:
                data = re.sub('^' + p[0] + '=[^&]*', p[0] + '=' + params[index], data)
                data = re.sub('&' + p[0] + '=[^&]*', '&' + p[0] + '=' + params[index], data)
            else:
                data += '&' + p[0] + '=' + params[index]
            index += 1
        index = 0    # replace something like {user} to its item val
        for p in selected_params:
            if data.find('{%s}' % p[0]) >= 0:
                data = data.replace('{%s}' % p[0], params[index])
        data = data.strip('&')
        if not args.nov:
            lock.acquire()
            print 'try', data
            lock.release()
        while True:
            try:
                if args.proxy_on:
                    if args.scm == 'https':    # request via proxy server
                        conn = httplib.HTTPSConnection(args.proxy)
                        if args.netloc.find(':') > 0:
                            conn.set_tunnel(args.host, int(args.netloc.split(':')[1]) )    # not port 443
                        else:
                            conn.set_tunnel(args.host, 443)
                    else:
                        conn = httplib.HTTPConnection(args.proxy)
                    if args.m == 'POST':
                        conn.request(method=args.m,
                                     url=args.scm + '://' + args.netloc + args.path,
                                     body=data,
                                     headers=headers)
                    else:    # get, need full url
                        conn.request(method=args.m,
                                     url=args.scm + '://' + args.netloc + args.path + '?' + data,
                                     headers=headers)
                else:    # proxy off
                    if args.scm == 'https':
                        conn = httplib.HTTPSConnection(args.netloc)
                    else:
                        conn = httplib.HTTPConnection(args.netloc)
                    if args.m == 'POST':
                        conn.request(method=args.m, url=args.path, body=data, headers=headers)
                    else:
                        conn.request(method=args.m, url=args.path + '?' + data, headers=headers)
                response = conn.getresponse()
                res_headers = str( response.getheaders() )
                charset = re.search('charset=([^"^>^\']*)', res_headers)    # try to find CharSet in headers
                if charset:
                    charset = charset.group(1)
                html_doc = decode_response_text( response.read(), charset)
                html_doc = html_doc.replace('\r\n', '\\r\\n')
                html_doc = html_doc.replace('\r', '\\r')
                html_doc = html_doc.replace('\n', ' \\n')
                html_doc = html_doc.replace('\t', ' ')
                html_doc = html_doc.replace('  ', ' ')
                # Debug On
                if args.debug:
                    lock.acquire()
                    print '#' * 4, 'DEBUG on, response headers and response text section ', '#' * 5
                    print res_headers
                    print ''
                    if os.name =='nt':
                        print html_doc.encode('gbk','ignore')
                    else:
                        print html_doc
                    print '#' * 64
                    lock.release()
                if (not args.no302 and response.status == 302) or \
                   (args.err and html_doc.find(args.err) < 0) or \
                   (args.suc and html_doc.find(args.suc) >=0 ) or \
                   (args.herr and res_headers.find(args.herr) < 0) or \
                   (args.hsuc and res_headers.find(args.hsuc) >=0 ):
                    lock.acquire()
                    print '>>> Found %s <<<' % data
                    with open(args.o, 'a') as outFile:
                        outFile.write(data + '\n')
                    lock.release()
                conn.close()
                break
            except Exception, e:
                print 'Error occured while handling request:', e
                time.sleep(3.0)    # retry 3 seconds later
        queue.task_done()


def decode_response_text(str, lang):
    if lang:
        try:
            return str.decode(lang)
        except:
            pass
    langs = ['UTF-8', 'GB2312', 'GBK', 'iso-8859-1', 'big5']
    for lang in langs:
        try:
            return str.decode(lang)
        except:
            pass
    try:
        return str.decode('ascii', 'ignore')
    except:
        pass
    raise Exception('Can not decode webpage')

threads = []
for i in range(args.t):
    t = threading.Thread(target=do_request)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print 'Task done on # %s #! All threads exit' % time.asctime()