htpwdScan是一个HTTP(S)弱口令扫描脚本，它的特点是:

1) 支持HTTP(S)代理扫描

2) 字典序列的生成和破解并行，可以为多个表单元素导入字典，可导入超大字典文件

3) 可以抓包后从文件导入HTTP请求

4) 通过设置X-Forwarded-For可随机伪造源IP

4) 在Linux和安装python的Windows系统下工作


参数说明：

  -h, --help            查看帮助
  -f REQUESTFILE        从文件载入HTTP请求，如: -f=post.txt
  -u REQUESTURL         显式设定请求的URL，如 -u=http://www.test.com/login.php
  -m METHOD             当使用-u设定URL时，可通过 -m=GET 显式设定为GET请求,
                        默认POST
  -https                使用 -f 从文件导入请求时，若为https，请设定 -https
  -d Param=DictFilePath [Param=DictFilePath ...]
                        为各表单元素设置字典，例如 -d user=users.dic pass=pass.dic
  -t THREADS            工作线程数，默认50
  -err ERR              响应文本中的错误标记，出现表示失败
  -suc SUC              响应文本中的成功标记，出现表示成功
  -herr HERR            响应头headers中的错误标记，出现表示失败
  -hsuc HSUC            响应头headers中的成功标记，出现表示成功
  -proxy Server:Port    设置HTTP代理，如: 127.0.0.1:8000
  -no302                302重定向不敏感, 默认是敏感
  -fip                  伪造随机源IP
  -o OUTPUT             输出文件路径, 默认 Cracked_Pass.txt
  -nov                  不显示详细进度, 只打印破解成功的
  -debug                调试，通过测试发送一次HTTP请求判断脚本是否工作正常


my[at]lijiejie.com      http://www.lijiejie.com
