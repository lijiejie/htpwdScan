htpwdScan是一个HTTP(s)弱口令扫描脚本，它的特点是:

1) 支持HTTP代理扫描，支持批量导入大量HTTP代理来绕过IP条件过滤

2) 字典序列的生成和破解并行，可为多个表单元素导入字典，可导入超大的字典文件,可MD5、SHA1 hash

3) 可以抓包后从文件导入HTTP请求

4) 可X-Forwarded-For随机伪造源IP

5) 可指定重试条件，比如遇到ngix指到不同后端服务器上，响应不同，或者是服务不稳定


运行环境:  python 2.7+


参数说明：

  -h, --help            show this help message and exit
  -f REQUESTFILE        Load HTTP request from file
  -https                Set -https only when load request from POSTFILE and
                        SSL was enabled
  -u REQUESTURL         Explicitly Set request URL
  -m METHOD             Set -m=GET only when -u was set and method is GET,
                        default is POST
  -d Param=DictFilePath [Param=DictFilePath ...]
                        set dictionary for each parameter,
                        support hash function like md5, md5_16, sha1. e.g.
                        -d user=users.dic pass=md5(pass.dic)
  -err ERR [ERR ...]    String indicates fail in response text, e.g.
                        -err "user not exist" "password wrong"
  -suc SUC [SUC ...]    String indicates success in response text, e.g.
                        -suc "welcome," "admin"
  -herr HERR            String indicates fail in response headers
  -hsuc HSUC            String indicates success in response headers
  -proxy Server:Port    Set HTTP proxies, e.g.
                        -proxy=127.0.0.1:8000,8.8.8.8:8000
  -proxylist ProxyListFile
                        Load HTTP proxies from file, one proxy per line, e.g.
                        -proxylist=proxy.txt
  -no302                302 redirect insensitive, default is sensitive
  -fip                  Spoof source IP
  -t THREADS            default 50 threads
  -o OUTPUT             Output file, defaut is Cracked_Pass.txt
  -rtxt RetryText       Retry when it appears in response text,
                        e.g. -rtxt="IP blocked"
  -rntxt RetryNoText    Retry when it does not appear in response text,
                        e.g. -rntxt="<body>"
  -rheader RetryHeader  Retry when it appears in response headers,
                        e.g. -rheader="Set-Cookie:"
  -rnheader RetryNoHeader
                        Retry when it didn't appear in response headers,
                        e.g. -rheader="Content-Length:"
  -sleep SECONDS        Sleep some time after each request,
                        avoid IP blocked by web server
  -nov                  Do not print verbose info, only print cracked ones
  -debug                Send a request and check
                        response headers and response text
  -v                    show program's version number and exit

my[at]lijiejie.com      http://www.lijiejie.com

Update log:
2014/6/23    Bug Fixed. Add support for loading HTTP proxies from file under development.
2014/6/24    Can set more than one HTTP porxy, e.g. -proxy=1.1.1.1:8000,2.2.2.2:8000
             Simplify output.