#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
htpwdScan v1.0
A simple and fast HTTP weak pass brute tool
By LiJieJie (my[at]lijiejie.com)
"""

import threading
import time
from lib.consle_width import CONSOLE_WIDTH
from lib.cmdline import parse_args
from lib.proxy import load_proxy
from lib.queue import gen_queue
from lib.url_parser import parse_request
from lib.request import do_request
from colorama import init, Fore, Back, Style

init(autoreset=True)


class Scanner(object):
    def __init__(self):
        self.cracked_count = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.STOP_ME = False
        self.args = parse_args()
        self.request_thread_count = self.args.t
        self.request_count = 0
        parse_request(self)
        load_proxy(self)
        self.gen_params_queue()
        if self.args.auth:
            self.auth_mode = 'Basic'    # default is basic auth
            do_request(self, auth_schema_test=True)
        elif self.args.check_proxy:
            pass
        else:
            do_request(self, request_test=True)

    def gen_params_queue(self):
        threading.Thread(target=gen_queue, args=(self,)).start()

    def print_s(self, _str, color=None):
        self.lock.acquire()
        if not color:
            print(_str)
        else:
            _str += Style.RESET_ALL
            if color == 'success':
                print(Back.GREEN + Fore.WHITE + _str)
            elif color == 'warning':
                print(Back.YELLOW + Fore.WHITE + _str)
            elif color == 'info':
                print(Back.CYAN + Fore.WHITE + _str)
            elif color == 'error':
                print(Back.RED + Fore.WHITE + _str)
            elif color == 'title':
                print(Back.LIGHTYELLOW_EX + Fore.RED + _str)
            else:
                print(Back.CYAN + Fore.WHITE + _str)
        self.lock.release()

    @staticmethod
    def now_time():
        return time.strftime('%H:%M:%S', time.localtime())

    def thread_exit(self):
        self.lock.acquire()
        self.request_thread_count -= 1
        self.lock.release()

    def run(self):
        self.print_s('[+] Job started at %s' % self.now_time())
        for i in range(self.args.t):
            t = threading.Thread(target=do_request, args=(self,))
            t.setDaemon(True)
            t.start()
        try:
            while self.request_thread_count > 0:
                time.sleep(0.1)
            self.print_s('_' * CONSOLE_WIDTH + '\nTask done at %s, time cost %.2f seconds' %
                         (self.now_time(), time.time() - self.start_time))
        except KeyboardInterrupt as e:
            self.STOP_ME = True
            time.sleep(1.0)
            self.print_s('_' * CONSOLE_WIDTH + '\n[KeyboardInterrupt] Task aborted at %s, cost %.2f seconds' %
                         (self.now_time(), time.time() - self.start_time))

        if self.args.check_proxy:
            if self.cracked_count:
                self.print_s('Found %s proxy server(s) in total, save to %s' % (self.cracked_count, self.args.o))
            else:
                self.print_s('No proxy servers found.')
        else:
            if self.cracked_count:
                self.print_s('Cracked %s item(s) in total, save to %s' % (self.cracked_count, self.args.o),
                             color='success')
            else:
                self.print_s('No one was cracked.')
        self.print_s('Total requests count: %s' % (self.request_count + 1))


if __name__ == '__main__':
    s = Scanner()
    s.run()
