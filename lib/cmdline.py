#!/usr/bin/env python
#
#  Parse command line arguments
#

import argparse
import sys
import os
import pprint
from colorama import Fore, Back
import re
from lib.consle_width import CONSOLE_WIDTH


def parse_args():
    parser = argparse.ArgumentParser(
        prog='htpwdScan',
        formatter_class=argparse.RawTextHelpFormatter,
        description='* HTTP weak pass scanner. By LiJieJie *',
        usage='htpwdScan.py [options]')

    target = parser.add_argument_group('Target')
    target.add_argument('-u', metavar='RequestURL', type=str,
                        help='URL to brute, e.g.\n-u "https://www.test.com/login.php"')
    target.add_argument('-f', metavar='RequestFile', type=str,
                        help='Load HTTP request from file')
    target.add_argument('--https', default=False, action='store_true',
                        help='Force https when load request from file\n')
    target.add_argument('--get', default=False, action='store_true',
                        help='Force use HTTP GET, default is POST')
    target.add_argument('--auth', metavar='', type=str, nargs='+',
                        help='Basic/Digest/NTLM auth brute, \n'
                             'e.g. --auth users.txt pass.txt\n'
                             'e.g. --auth users.txt my_own_func(pass.txt)\n'
                             'e.g. --auth user_and_pass.txt')
    target.add_argument('--pass-first', default=False, action='store_true',
                        help='To avoid accounts locked, \n'
                             'try different usernames on one password first')

    dictionary = parser.add_argument_group('Dictionary')
    dictionary.add_argument('-d', metavar='Param=DictFile', type=str, nargs='+',
                            help='Set dict file for parameters, \n'
                                 'support hash functions: md5, md5_16, sha1 \n'
                                 'e.g. -d user=users.dic pass=md5(pass.dic) \n'
                                 'support user defined functions in lib/value_process.py\n'
                                 'e.g. -d user=users.dic pass=capitalize(pass.dic)')

    detect = parser.add_argument_group('Detect')
    detect.add_argument('--no302', default=False, action='store_true',
                        help='302 redirect insensitive, default: sensitive')
    detect.add_argument('--fail', metavar='Fail', default='', type=str, nargs='+',
                        help='String indicates fail in response text, \ne.g. --fail "user not exist" "password wrong"')
    detect.add_argument('--suc', metavar='Suc', default='', type=str, nargs='+',
                        help='String indicates success in response text, \ne.g. --suc "welcome," "logout"')
    detect.add_argument('--header-fail', metavar='HeaderFail', default='', type=str,
                        help='String indicates fail in response headers')
    detect.add_argument('--header-success', metavar='HeaderSuccess', default='', type=str,
                        help='String indicates success in response headers')
    detect.add_argument('--retry-txt', metavar='RetryText', type=str, default='',
                        help='Retry when it appears in response text, \ne.g. --retry-txt="IP blocked"')
    detect.add_argument('--retry-no-txt', metavar='RetryNoText', type=str, default='',
                        help='Retry when it does not appear in response text, \ne.g. --retry-no-txt="<body>"')
    detect.add_argument('--retry-header', metavar='RetryHeader', type=str, default='',
                        help='Retry when it appears in response headers, \ne.g. --retry-header="Set-Cookie:"')
    detect.add_argument('--retry-no-header', metavar='RetryNoHeader', type=str, default='',
                        help='Retry when it didn\'t appear in response headers, \n'
                             'e.g. --retry-no-header="HTTP/1.1 200 OK"')

    proxy_spoof = parser.add_argument_group('Proxy and Spoof')
    proxy_spoof.add_argument('--proxy', metavar='Proxy', default='', type=str,
                             help='Set HTTP proxies from command line \n'
                                  'e.g. --proxy=1.2.3.4:8000, 5.6.7.8:8000')
    proxy_spoof.add_argument('--proxy-file', metavar='ProxyFile', default='', type=str,
                             help='Load HTTP proxies from file, delimited by line feed, \n'
                                  'e.g. --proxy-file=proxies.txt')
    proxy_spoof.add_argument('--check-proxy', default=False, action='store_true',
                             help='Validate proxy servers\' status')
    proxy_spoof.add_argument('--fake-ip', default=False, action='store_true',
                             help='Spoof source IP by random X-Forwarded-For')
    proxy_spoof.add_argument('--fake-sid', type=str, metavar='FakeSID',
                             help='Use a random session ID. e.g. --fake-sid PHPSESSID')

    database = parser.add_argument_group('Database attack')
    database.add_argument('--database', metavar='param1,parma2=file', type=str,
                          help='Load leaked passwords to attack. \ne.g. --database user,pass=csdn.txt')
    database.add_argument('--regex', type=str,
                          help='Regex pattern to extract values. \n'
                               r'e.g. --regex="(\S+)\s+(\S+)"')

    general = parser.add_argument_group('General')
    general.add_argument('-t', metavar='Threads', type=int, default=50,
                         help='Number of HTTP request threads, 50 threads by default')
    proxy_spoof.add_argument('--sleep', metavar='Seconds', type=str, default='',
                             help='Sleep N seconds after each request to avoid IP blocked by web server')
    general.add_argument('--allow-redirect', default=False, action='store_true',
                         help='Allow follow 30x redirect, disallow by default')
    general.add_argument('-o', metavar='OutFile', type=str, default='',
                         help='Output file name')
    general.add_argument('--debug', default=False, action='store_true',
                         help='Enter debug mode to inspect request and response')
    general.add_argument('--silent', default=False, action='store_true',
                         help='No verbose output, only print cracked ones')
    general.add_argument('-v', action='version', version='%(prog)s 1.0')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()

    check_args(args)
    if args.debug:
        # thread set to 1 in debug mode
        args.t = 1
        print(Back.LIGHTYELLOW_EX + Fore.RED + '[ Parsed Arguments ]')
        pprint.pprint(args.__dict__)
        print('\n' + '*' * CONSOLE_WIDTH)
    return args


def check_args(args):
    try:
        if not args.o:
            args.o = '_proxy.servers.txt' if args.check_proxy else '_cracked.accounts.txt'

        if not args.f and not args.u:
            msg = 'RequestFILE or RequestURL required, set with -f or -u'
            raise Exception(msg)

        if args.auth:
            if len(args.auth) not in [1, 2]:
                msg = 'One or two dict files required: --auth users.dic pass.dic / --auth leaked_db.txt'
                raise Exception(msg)

            for _file in args.auth:
                file_not_found = True
                if os.path.exists(_file):
                    file_not_found = False
                else:
                    m = re.search(r'.*\((.*?)\)', _file)
                    if m and os.path.exists(m.groups()[0]):
                        file_not_found = False
                if file_not_found:
                    raise Exception('Dict file not found: %s' % _file)

        if not args.auth and not args.check_proxy and not args.database:
            if not args.d:
                raise Exception('Please feed dict files. e.g. -d user=users.dic pass=md5(pass.dic)')

        if args.check_proxy and os.path.exists('proxy_servers_verified.txt'):
            os.remove('proxy_servers_verified.txt')

        if args.database:
            data_file = args.database.split('=')[1]
            if not os.path.exists(data_file):
                raise Exception('Database file not found: %s' % data_file)
            if not args.regex:
                raise Exception(r'Please set --regex to extract data. \ne.g. --regex "(\S+)\s+(\S+)"')
    except Exception as e:
        print(Back.LIGHTYELLOW_EX + Fore.RED + '[ERROR] ' + str(e))
        exit(-1)
