#!/usr/bin/env python
# encoding=utf-8
#
# Generate parameters queue
#

import time
import queue
import os
import re
from colorama import Fore, Back, Style
from inspect import getmembers, isfunction
from lib.consle_width import CONSOLE_WIDTH
import lib.value_process


def gen_queue_auth(scanner):
    for i in range(2):
        m = re.search(r'(.*)\((.*?)\)', scanner.args.auth[i])
        if m:
            func_name, scanner.args.auth[i] = m.groups()
            if func_name not in scanner.user_functions:
                scanner.print_s('[ERROR] Function %s is unavailable' % func_name, color='error')
                scanner.print_s('Functions available: %s' % ', '.join(scanner.user_functions.keys()), color='info')
                exit(-1)
            else:
                scanner.selected_params[i] = scanner.user_functions[func_name]

    if scanner.args.pass_first:
        f_first = open(scanner.args.auth[1], 'r')
        f_second = open(scanner.args.auth[0], 'r')
    else:
        f_first = open(scanner.args.auth[0], 'r')
        f_second = open(scanner.args.auth[1], 'r')

    for val_1 in f_first:
        f_second.seek(0)    # Must start from beginning
        for val_2 in f_second:
            if scanner.args.pass_first:
                auth_info = [val_2.strip(), val_1.strip()]
            else:
                auth_info = [val_1.strip(), val_2.strip()]
            while scanner.queue.qsize() >= scanner.args.t * 2 and not scanner.STOP_ME:
                time.sleep(0.001)
            scanner.queue.put(auth_info)
            if scanner.args.debug or scanner.STOP_ME:
                break
        if scanner.args.debug or scanner.STOP_ME:
            break

    f_first.close()
    f_second.close()

    for i in range(scanner.args.t):
        scanner.queue.put(None)


def gen_queue_database(scanner):
    _, db_file = scanner.args.database.split('=')
    params = _.split(',')
    for param in params:
        m = re.search(r'(.*)\((.*?)\)', param)
        if m:
            func_name, param = m.groups()
            if func_name not in scanner.user_functions:
                scanner.print_s('[ERROR] Function %s is unavailable' % func_name, color='error')
                scanner.print_s('Functions available: %s' % ', '.join(scanner.user_functions.keys()), color='info')
                exit(-1)
            else:
                scanner.selected_params[param] = {'func': scanner.user_functions[func_name]}
        else:
            scanner.selected_params[param] = {}

    params_count = len(params)

    pattern = re.compile(scanner.args.regex)
    db_file = open(db_file, 'r')
    for line in db_file:
        if scanner.STOP_ME:
            break

        line = line.strip()
        m = pattern.search(line)

        if not m or len(m.groups()) != params_count:
            continue
        while scanner.queue.qsize() >= scanner.args.t * 2 and not scanner.STOP_ME:
            time.sleep(0.001)
        scanner.queue.put('^^^'.join(m.groups()))

        if scanner.args.debug:
            break
    db_file.close()


def gen_python_code(scanner):
    str_code = str_code_prefix = str_code_postfix = ''
    indent = 0
    for param in scanner.args.d:
        para_name, file_name = param.split('=')
        m = re.search(r'(.*)\((.*?)\)', file_name)
        if m:
            func_name, file_name = m.groups()
            if func_name not in scanner.user_functions:
                scanner.print_s('[ERROR] Function %s is unavailable' % func_name, color='error')
                scanner.print_s('Functions available: %s' % ', '.join(scanner.user_functions.keys()), color='info')
                exit(-1)
            else:
                scanner.selected_params[para_name] = {
                    'func': scanner.user_functions[func_name],
                    'file': file_name}
        else:
            scanner.selected_params[para_name] = {'file': file_name}
        if not os.path.exists(file_name):
            raise Exception('File not found: %s' % file_name)

        str_code += ' ' * 4 * indent
        indent += 1
        str_code_prefix += "file" + str(indent) + " = open(r'" + file_name + "', 'r')\n"    # prefix
        str_code += "file" + str(indent) + ".seek(0)\n"
        str_code += ' ' * 4 * (indent - 1)
        str_code += "for line" + str(indent) + " in file" + str(indent) + ":\n"
        str_code_postfix += 'file' + str(indent) + '.close()\n'    # postfix

    str_code += ' ' * 4 * indent + 'while not scanner.STOP_ME:\n'
    indent += 1
    str_code += ' ' * 4 * indent + 'if scanner.queue.qsize() < scanner.args.t * 2:\n'
    indent += 1
    str_code += ' ' * 4 * indent
    index = 1
    str_line = ''
    for _ in scanner.args.d[:-1]:
        str_line += 'line' + str(index) + ".strip() + '^^^' + "    # values separated by '^^^'
        index += 1
    str_line += 'line' + str(index) + '.strip()'
    str_code += "scanner.queue.put(" + str_line + ")\n"
    str_code += ' ' * 4 * indent + 'break\n'
    str_code += ' ' * 4 * (indent - 1) + 'time.sleep(0.001)\n'
    if scanner.args.debug:
        for i in range(len(scanner.args.d)):
            str_code += ' ' * 4 * (indent - 2 - i) + 'break\n'
    str_code += 'for i in range(scanner.args.t):\n    scanner.queue.put(None)\n'
    str_code = str_code_prefix + str_code + str_code_postfix.strip()
    return str_code


def gen_queue(scanner):

    scanner.queue = queue.Queue()
    scanner.user_functions = {}
    for f in getmembers(lib.value_process, isfunction):
        scanner.user_functions[f[0]] = f[1]

    scanner.selected_params = {}    # {'param': md5}

    if scanner.args.auth:
        gen_queue_auth(scanner)
        return

    elif scanner.args.check_proxy:
        count = 1 if scanner.args.debug else len(scanner.proxy_list)
        for _ in range(count):
            scanner.queue.put('')
        for _ in range(count):
            scanner.queue.put(None)
        return

    elif scanner.args.database:
        gen_queue_database(scanner)
        return

    else:
        str_code = gen_python_code(scanner)
        scanner.lock.acquire()
        if scanner.args.debug:
            time.sleep(1.0)
            print(Back.LIGHTYELLOW_EX + Fore.RED + '[ Python code for queue ]' + Style.RESET_ALL)
            print(str_code)
            print('\n' + '*' * CONSOLE_WIDTH)
        scanner.lock.release()
        exec(str_code)
