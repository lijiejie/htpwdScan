#!/usr/bin/env python
#
# Load proxy from command line or text file
#

import os
from lib.consle_width import CONSOLE_WIDTH
from colorama import Fore, Back


def load_proxy(scanner):
    try:
        scanner.proxy_on = False
        scanner.proxy_list = []
        scanner.proxy_index = 0

        if scanner.args.proxy:
            for item in scanner.args.proxy.split(','):
                item = item.strip()
                if len(item) >= 7 and item.find(':') > 0:
                    scanner.proxy_list.append(item)

            if scanner.proxy_list:
                scanner.proxy_on = True
            else:
                raise Exception('Invalid proxy Server! Feed sth like 1.2.3.4:8080 or https://1.2.3.4:8888')

        # Load HTTP proxies from file
        if scanner.args.proxy_file:
            if not os.path.exists(scanner.args.proxy_file):
                raise Exception('Proxy list file not found!')

            with open(scanner.args.proxy_file, 'r') as inFile:
                for line in inFile:
                    line = line.strip()
                    if line.find(':') > 0 and len(line) >= 7 and line[line.rfind(':')+1:].strip().isdigit():
                        scanner.proxy_list.append(line)

            if scanner.proxy_list:
                scanner.proxy_on = True
            else:
                raise Exception('Fail to load HTTP proxies from file: no valid proxies')

        if scanner.args.debug and scanner.proxy_list:
            scanner.lock.acquire()
            print('[ Proxy servers loaded ]\n')
            print(scanner.proxy_list)
            print('\n' + '*' * CONSOLE_WIDTH)
            scanner.lock.release()

        if scanner.args.check_proxy and not scanner.proxy_list:
            raise Exception('No proxy servers found, set with --proxy or --proxy-file')

    except Exception as e:
        print(Back.LIGHTYELLOW_EX + Fore.RED + '[ERROR] ' + str(e))
        exit(-1)
