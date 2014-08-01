#!/usr/bin/env python
# encoding=utf-8

'''

htpwdScan v 0.0.2
An HTTP(s) weak pass scanner 
my[at]lijiejie.com

Under development:
    1. Add IP spoof support by loading handreds of HTTP proxies from a file: Done
    2. Add hashing support for parameters: Done
    3. Add HTTP basic auth support: Done

To do:
    4. Verify thousands of HTTP proxies from File

'''


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
import hashlib
import base64
import copy    # deepcopy

#
#  Parse command line arguments
#

def get_args():
    parser = argparse.ArgumentParser(prog='htpwdScan',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description='* An HTTP/HTTPS weakpass scanner. By LiJiejie *')
    parser.add_argument('-f', metavar='REQUESTFILE', type=str,
                        help='Load HTTP request from file')
    parser.add_argument('-https', default=False, action='store_true',
                        help='Set -https only when load request from file and \nHTTPS was enabled')    # 2014/6/30
    parser.add_argument('-u', metavar='REQUESTURL', type=str,
                        help='Explicitly Set request URL, e.g.\n' + \
                        '-u="http://www.test.com/login.php"')
    parser.add_argument('-m', metavar='METHOD', type=str, default='POST',
                        choices=['POST', 'GET'],
                        help='Set -m=GET only when -u was set and request method \nis GET,default is POST')
    parser.add_argument('-basic', metavar='',type=str, nargs='+',
                        help='HTTP Basic Auth brute, e.g. -basic users.dic pass.dic')    # add basic auth support 2014/7/31
    parser.add_argument('-d', metavar='Param=DictFilePath', type=str, nargs='+',
                        help='set dict file for each parameter, \n' + \
                        'support hash functions like md5, md5_16, sha1. e.g.\n' + \
                        '-d user=users.dic pass=md5(pass.dic)')
    parser.add_argument('-no302', default=False, action='store_true',
                        help='302 redirect insensitive, default is sensitive')
    parser.add_argument('-err', metavar='ERR', default='', type=str, nargs='+',
                        help='String indicates fail in response text, e.g.\n-err "user not exist" "password wrong"')
    parser.add_argument('-suc', metavar='SUC', default='', type=str, nargs='+',
                        help='String indicates success in response text, e.g.\n-suc "welcome," "admin"')
    parser.add_argument('-herr', metavar='HERR', default='', type=str,
                        help='String indicates fail in response headers')
    parser.add_argument('-hsuc', metavar='HSUC', default='', type=str,
                        help='String indicates success in response headers')
    parser.add_argument('-proxy', metavar='Server:Port', default='', type=str,
                        help='Set HTTP proxies, e.g.\n-proxy=127.0.0.1:8000,8.8.8.8:8000')
    parser.add_argument('-proxylist', metavar='ProxyListFile', default='', type=str,    # added on 2014-6-23
                        help='Load HTTP proxies from file, one proxy per line, e.g.\n-proxylist=proxys.txt')
    parser.add_argument('-fip', default=False, action='store_true',
                        help='Spoof source IP')
    parser.add_argument('-t', metavar='THREADS', type=int, default=50,
                        help='50 threads by default')
    parser.add_argument('-o', metavar='OUTPUT', type=str, default='Cracked_Pass.txt',
                        help='Output file, defaut is Cracked_Pass.txt')
    parser.add_argument('-rtxt', metavar='RetryText', type=str, default='',    # added on 2014-6-23
                        help='Retry when it appears in response text, \ne.g. -rtxt="IP blocked"')
    parser.add_argument('-rntxt', metavar='RetryNoText', type=str, default='',    # added on 2014-6-26
                        help='Retry when it does not appear in response text, \ne.g. -rntxt="<body>"')
    parser.add_argument('-rheader', metavar='RetryHeader', type=str, default='',    # added on 2014-6-23
                        help='Retry when it appears in response headers, \ne.g. -rheader="Set-Cookie:"')
    parser.add_argument('-rnheader', metavar='RetryNoHeader', type=str, default='',    # added on 2014-6-26
                        help='Retry when it didn\'t appear in response headers, \ne.g. -rheader="Content-Length:"')
    parser.add_argument('-sleep', metavar='SECONDS', type=str, default='',    # added on 2014-6-24
                        help='Sleep some time after each request,\navoid IP blocked by web server')
    parser.add_argument('-debug', default=False, action='store_true',
                        help='Send a request and check \nresponse headers and response text')
    parser.add_argument('-nov', default=False, action='store_true',
                        help='Do not print verbose info, only print the cracked ones')
    parser.add_argument('-v', action='version', version='%(prog)s 0.0.2')
    if len(sys.argv) == 1:    # show help msg while no args
        sys.argv.append('-h')
    return parser.parse_args()

args = get_args()


#
# System specific encoding and decoding
# Use gbk under Windows
# Use utf-8 under Linux
#

def system_encode(istr):
    if os.name == 'nt':
        return istr.encode('gbk', 'ignore')
    else:
        return istr.encode('utf-8', 'ignore')

def system_decode(istr):
    if os.name == 'nt':
        return istr.decode('gbk', 'ignore')
    else:
        return istr.decode('utf-8', 'ignore')

#
# decode error tags and success tags
#
if len(args.err) > 0:
    for i in range( len(args.err) ):
        args.err[i] = system_decode(args.err[i])
if len(args.suc) > 0:
    for i in range( len(args.suc) ):
        args.suc[i] = system_decode(args.suc[i])

#
# decode retry text and retry no text, added on 2014/7/3
#

if args.rtxt:
    args.rtxt = system_decode(args.rtxt)
if args.rntxt:
    args.rntxt = system_decode(args.rntxt)


if args.f == None and args.u == None:
    raise Exception('Both RequestFILE and RequestURL are missing!\n' + \
                    ' ' * len('Exception: ')  + 'Use -f or -u to set one')

if args.basic:
    if len(args.basic) != 2:
        raise Exception('Two dict files are required, e.g. \n' + ' ' * len('Exception: ') + '-basic users.dic pass.dic')
    for df in args.basic:
        if not os.path.exists(df):
            raise Exception('Dict file not exists:' + df)

if args.debug:
    args.t = 1    # debug on, thread set to 1
    print '#' * 13, 'DEBUG on, Below is arguments parsed:', '#' * 13
    print args
    print '#' * 64


#
# Proxy enablded
# I will not check weather the proxy server works fine, please do it yourself
#
proxy_list = []
args.proxy_on = False
if args.proxy:
    for proxy_item in args.proxy.split(','):
        proxy_item = proxy_item.strip()
        if len(proxy_item) >= 10 and proxy_item.find(':') > 0:    
            proxy_list.append(proxy_item)
            args.proxy_on = True
    if len(proxy_list) < 1:
        raise Exception('Invalid Proxy Server!')
    else:
        args.proxy_on = True
#
# Load HTTP proxies from a file
#
if args.proxylist:
    if not os.path.exists(args.proxylist):
        raise Exception('Proxy list file not found!')
    
    with open(args.proxylist, 'r') as inFile:
        while True:
            line = inFile.readline().strip()
            if len(line) < 1: break
            if line.find(':') > 0 and len(line) >= 10:
                proxy_list.append(line)
    if len(proxy_list) < 1:
        raise Exception('Fail to load HTTP proxies from file!')
    else:
        args.proxy_on = True
    if args.debug:
        print '#' * 16, 'DEBUG on, below is proxy list', '#' * 17
        print proxy_list
        print '#' * 64
        

print 'Job started on # %s #' % time.asctime()


#
# Generate parameters queue asynchronously
#

queue = Queue.Queue()
selected_params = []    # target parameters
args.md5 = []
args.md5_16 = []
args.sha1 = []

def gen_queue():
    #
    # generate executable python code,
    # the code will be used to generate parameters queue
    # Bug fixed, all files will be closed. 2014/6/30
    # Bug fixed, file must seek 0 after each loop. 2014/6/30
    #
    
    # HTTP basic auth
    if args.basic:
        f_user = open(args.basic[0], 'r')
        f_pass = open(args.basic[1], 'r')
        for str_user in f_user.xreadlines():
            f_pass.seek(0)    # be careful we need seek 0
            for str_pass in f_pass.xreadlines():
                auth_key = str_user.strip() + ':' + str_pass.strip()
                while True:
                    if queue.qsize() < args.t:
                        queue.put(auth_key)
                        break
                    else:
                        time.sleep(0.001)
                if args.debug:
                    break
            if args.debug:
                break
        f_user.close()
        f_pass.close()
        for i in range(args.t):
            queue.put(None)
        return
                    
    str_code = ''
    str_code_prefix = ''
    str_code_postfix = ''
    indent = 0
    for param in args.d:
        pname = param.split('=')[0].strip()    # parameter name
        fname = param.split('=')[1].strip()    # dict file name
        if fname[:4].lower() == 'md5(' and fname[-1:] == ')':    # MD5 32-bit hashing
            args.md5.append(pname)
            fname = fname[4: -1]
        elif fname[:7].lower() == 'md5_16(' and fname[-1:] == ')':    # MD5 16-bit hashing
            args.md5_16.append(pname)
            fname = fname[7: -1]
        elif fname[:5].lower() == 'sha1(' and fname[-1:] == ')':    # SHA1 40-bit hashing
            args.sha1.append(pname)
            fname = fname[5: -1]
        selected_params.append( (pname, fname) )    # e.g ('user', 'user.dic')
        str_code += '    ' * indent
        indent += 1
        str_code_prefix += "file" + str(indent) + " = open(r'" + fname + "', 'r')\n"    # prefix
        str_code += "file" + str(indent) + ".seek(0)\n"
        str_code += '    ' * (indent - 1)
        str_code += "for line" + str(indent) + " in file" + str(indent) + ":\n"
        str_code_postfix += 'file' + str(indent) + '.close()\n'    # postfix
    str_code += '    ' * indent + 'while True:\n'
    indent += 1
    str_code += '    ' * indent + 'if queue.qsize() < args.t:\n'
    indent += 1
    str_code += '    ' * indent
    index = 1
    str_line = ''
    for param in args.d[:-1]:
        str_line += 'line' + str(index) + ".strip() + '^^^' + "    # values splited by '^^^'
        index += 1
    str_line += 'line' + str(index) + '.strip()'
    str_code += "queue.put(" + str_line + ")\n"
    str_code += '    ' * indent + 'break\n'
    str_code += '    ' * (indent - 1) + 'time.sleep(0.001)\n'
    if args.debug:
        for i in range(len(args.d)):
            str_code += '    ' * (indent - 2 - i) + 'break\n'
    str_code += 'for i in range(args.t):\n    queue.put(None)\n'
    str_code = str_code_prefix + str_code + str_code_postfix.strip()
    if args.debug:
        print '#' * 14, 'DEBUG on, below is generated code', '#' * 15
        print str_code
        print '#' * 64
    exec(str_code)

threading.Thread(target=gen_queue).start()   # put parameters in queue

#
# Parse HTTP request from file
#

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
        first_line = lines[0].strip()
        if first_line.find('GET ') == 0:
            args.m = 'GET'
        else:
            args.m = 'POST'
        args.path = first_line.split(' ')[1]
        if args.path.find('://') > 0:
            args.path = args.path.replace('://', '')
            args.path = args.path[args.path.find('/') :]
        args.netloc = re.search('Host: (.*)', post_text).group(1).strip()    # host name, bug fixed on 2014-6-23
        if args.m == 'POST':    # find query data
            for i in range(len(lines) -1 , 0, -1):
                if len(lines[i].strip()) > 0:
                    args.query = lines[i].strip()
                    break
        else:    # deal with GET
            (scm, netloc, args.path, params, args.query, fragment) = urlparse.urlparse(args.path)

        # deal with headers, be careful do not accecpt encoding-gzip
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

    args.netloc = args.netloc.strip()    # added on 2014/6/24
    args.query = args.query.strip()
    headers['Cache-Control'] = 'no-cache'
    if args.m == 'POST':
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
    if args.netloc.find(':') < 0:    # under Linux, host_name and port are both required
        args.host = args.netloc.strip()
        args.host_port = 80
    else:
        args.host, args.host_port = args.netloc.split(':')
        args.host = args.host.strip()
        args.host_port = int(args.host_port)
        
parse_request()

#
# Handle HTTP Request
#

lock = threading.Lock()
proxy_index = 0

def do_request():
    while True:
        params = queue.get()
        if params == None:
            queue.task_done()
            return
        local_headers = copy.deepcopy(headers)
        if args.basic:
            local_headers['Authorization'] = 'Basic ' + base64.b64encode(params)    # Basic auth: 2014/7/31
        data = args.query
        
        if not args.basic:
            params = params.split('^^^')    # e.g. params = ['user', 'passwd']
                        
            #
            # bug fixed on 2014/6/24, add urlencode for param value
            # Be careful when dealing with params
            # replace refference object first, later replace query string
            # at last urlencode
            # code below needs review 2014/6/30
            #

            index = 0        
            for p in selected_params:
                # refference
                index2 = 0
                for p2 in selected_params:
                    params[index] = params[index].replace('{%s}' % p2[0], params[index2])
                    index2 += 1
                index += 1
            
            data_output = ''    # optmized output        
            index = 0
            for p in selected_params:    # replace value for target parameter
                data_output += p[0] + '=' + params[index] + '&'
                # hash support: MD5, MD5_16, SHA1
                if args.md5.count(p[0]) > 0:
                    str_param = urllib.urlencode( {p[0]:  hashlib.md5(params[index]).hexdigest()} )
                elif args.md5_16.count(p[0]) > 0:
                    str_param = urllib.urlencode( {p[0]:  hashlib.md5(params[index]).hexdigest()[8:24]} )
                elif args.sha1.count(p[0]) > 0:
                    str_param = urllib.urlencode( {p[0]:  hashlib.sha1(params[index]).hexdigest()} )
                else:
                    str_param = urllib.urlencode( {p[0]:  params[index]} )

                if data.find(p[0] + '=') == 0 or \
                   data.find('&' + p[0] + '=') > 0:   # found in query
                    data = re.sub('^' + p[0] + '=[^&]*', str_param, data)    
                    data = re.sub('&' + p[0] + '=[^&]*', '&' + str_param, data)
                else:    # not found, appended to query string
                    data = data + '&' + str_param
                index += 1
                    
                data = data.strip('&')
                data_output = data_output.strip('&')
        
        if not args.nov:
            lock.acquire()
            if args.basic:
                print 'try', params
            else:
                print 'try', data_output
            lock.release()
        err_count = 0
        while err_count < 10:
            try:
                if args.proxy_on:
                    global proxy_list    # code moved here on 2014/6/30
                    global proxy_index
                    lock.acquire()    # fetch one proxy server
                    cur_proxy = proxy_list[proxy_index]
                    proxy_index += 1
                    if proxy_index > len(proxy_list) - 1:
                        proxy_index = 0
                    lock.release()    
                    pserver, pport = cur_proxy.split(':')
                    if args.scm == 'https':    # https request via proxy server
                        conn = httplib.HTTPSConnection(cur_proxy, timeout=30)
                        if args.netloc.find(':') > 0:
                            conn.set_tunnel(args.host, args.host_port )    # port may not be 443
                        else:
                            conn.set_tunnel(args.host, 443)
                    else:
                        conn = httplib.HTTPConnection(cur_proxy, timeout=30)
                    if args.fip:
                        local_headers['X-Forwarded-For'] = str(random.randint(1,255)) + '.' + \
                                                   str(random.randint(1,255)) + '.' + \
                                                   str(random.randint(1,255)) + '.' + \
                                                   str(random.randint(1,255))
                        local_headers['PHPSESSID'] = random.randint(1, 10000000000000)

                    # 
                    # Proxy server needs to know the full url
                    #
                    if args.m == 'POST':
                        conn.request(method=args.m,
                                     url=args.scm + '://' + args.netloc + args.path,
                                     body=data,
                                     headers=local_headers)
                    else:
                        conn.request(method=args.m,
                                     url=args.scm + '://' + args.netloc + args.path + '?' + data,
                                     headers=local_headers)
                else:    # proxy off
                    if args.scm == 'https':
                        conn = httplib.HTTPSConnection(args.netloc, timeout=30)
                    else:
                        conn = httplib.HTTPConnection(args.netloc, timeout=30)
                    if args.m == 'POST':
                        conn.request(method=args.m, url=args.path, body=data, headers=local_headers)
                    else:
                        conn.request(method=args.m, url=args.path + '?' + data, headers=local_headers)
                response = conn.getresponse()
                res_headers = str( response.getheaders() )
                charset = re.search('charset=([^"^>^\']*)', res_headers)    # try to find CharSet in headers
                if charset:
                    charset = charset.group(1).strip()
                html_doc = decode_response_text( response.read(), charset)
                conn.close()   # be careful
                html_doc = html_doc.replace('\r\n', '\\r\\n').replace('\r', '\\r').replace('\n', ' \\n').replace('\t', ' ')
                html_doc = re.sub(' +', ' ', html_doc)    # Only leave one blank char
                # Debug On
                if args.debug:
                    lock.acquire()
                    print '#' * 4, 'DEBUG on, response headers and response text section ', '#' * 5
                    print res_headers
                    print ''
                    print system_encode(html_doc)
                    print '#' * 64
                    lock.release()
                
                # Retry if server didn't give a resonable response 
                if args.rtxt and html_doc.find(args.rtxt) > 0:  
                    raise Exception('Retry for ' + system_encode(args.rtxt) )
                if args.rntxt and html_doc.find(args.rntxt) < 0:
                    raise Exception('Retry for no ' + system_encode(args.rntxt))
                if args.rheader and res_headers.find(args.rheader) > 0:
                    raise Exception('Retry for header ' + args.rheader)
                if args.rnheader and res_headers.find(args.rnheader) < 0:
                    raise Exception('Retry for no header ' + args.rnheader)
                
                if_err = False
                for i in range(len(args.err)):
                    if html_doc.find(args.err[i]) >= 0:
                        if_err = True
                if_suc = False
                suc_tag_matched = ''    # str matched in response text
                for i in range(len(args.suc)):
                    if html_doc.find(args.suc[i]) >= 0:
                        suc_tag_matched = args.suc[i]
                        if_suc = True
                        
                if (not args.no302 and response.status == 302) or \
                   (args.err and not if_err) or \
                   (args.suc and if_suc) or \
                   (args.herr and res_headers.find(args.herr) < 0) or \
                   (args.hsuc and res_headers.find(args.hsuc) >=0 ) or \
                   (args.basic and response.status != 401):
                    lock.acquire()
                    if not args.basic:
                        print system_encode( '>>> Found %s <<<' % data_output )
                        with open(args.o, 'a') as outFile:
                            if not args.no302 and response.status == 302:
                                outFile.write( system_encode( '[302] ' + data_output + '\n') )
                            elif args.suc and if_suc:
                                outFile.write( system_encode( '{' + suc_tag_matched + '} ' + data_output + '\n') )
                            else:
                                outFile.write( system_encode(data_output + '\n') )
                    else:    # args.basic
                        print system_encode( '>>> Found %s <<<' % params )
                        local_headers['Authorization'] = ''
                        with open(args.o, 'a') as outFile:
                            outFile.write( system_encode( str(response.status) + '[Basic Auth] ' + params + ' ' + args.u + '\n') )
                    lock.release()

                if args.sleep:
                    time.sleep( float(args.sleep) )    # sleep for a while
                break
            except Exception, e:
                err_count += 1
                lock.acquire()
                print 'Error occured while handling request:', e
                lock.release()
                try:
                    conn.close()
                except:
                    pass
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