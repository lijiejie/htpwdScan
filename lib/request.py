#!/usr/bin/env python
# encoding=utf-8
#
# Do HTTP request
#

import copy
import random
import re
import string
from urllib.parse import parse_qsl, unquote, urlencode, urlparse
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from requests_ntlm import HttpNtlmAuth
import time
import urllib3
from lib.consle_width import CONSOLE_WIDTH


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def add_cracked_count(scanner):
    scanner.lock.acquire()
    scanner.cracked_count += 1
    scanner.lock.release()


def get_proxy(scanner):
    scanner.lock.acquire()
    cur_proxy = scanner.proxy_list[scanner.proxy_index]
    scanner.proxy_index += 1
    if scanner.proxy_index > len(scanner.proxy_list) - 1:
        scanner.proxy_index = 0
    scanner.lock.release()
    if cur_proxy.lower().find('http') == -1:
        cur_proxy = 'http://' + cur_proxy
    _ = urlparse(cur_proxy)
    if _.scheme.lower() != 'https':
        cur_proxy = 'http://' + _.netloc
    else:
        cur_proxy = 'https://' + _.netloc
    return cur_proxy


def fake_ip(scanner, local_headers):
    if scanner.args.fake_ip:  # Random IP
        local_headers['X-Forwarded-For'] = local_headers['Client-IP'] = \
            '.'.join(str(random.randint(1, 255)) for _ in range(4))


def fake_session_id(scanner, local_headers):
    if scanner.args.fake_sid:  # Random session ID
        m = re.search('%s=([^;^ ]*)' % scanner.args.fsid, scanner.http_headers['Cookie'])
        if m:
            random_str = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(len(m.group(1))))
            local_headers['Cookie'] = local_headers['Cookie'].replace(
                m.group(0), '%s=%s' % (scanner.args.fsid, random_str))
        else:
            scanner.print_s('[Warning] Can not find session ID %s in cookie' % scanner.args.fsid, color='warning')


# auth schema test: test for Basic / Digest / NTLM
# request test: send a test_value to check response
def do_request(scanner, auth_schema_test=False, request_test=False):
    auth = None
    data_to_print = ''    # unquote string
    cur_proxy = ''
    origin_param_values = None
    local_request_count = 0

    while not scanner.STOP_ME:
        if auth_schema_test:
            scanner.print_s('[+] Check auth schema')
            param_values = ['not_existed_user', 'not_existed_password']
        elif request_test:
            if not scanner.args.debug:
                scanner.print_s('[+] Run request test')
            if request_test:
                time.sleep(0.1)    # wait for gen_python_code -> exec(str_code)
            # set all param_values to "test_value", test should return fail
            origin_param_values = param_values = '^^^'.join(['test_value' for _ in scanner.selected_params.keys()])
        else:
            try:
                origin_param_values = param_values = scanner.queue.get(timeout=1.0)
            except Exception as e:
                scanner.request_count += local_request_count
                scanner.thread_exit()
                return

            if param_values is None:
                scanner.queue.task_done()
                scanner.request_count += local_request_count
                scanner.thread_exit()
                return

        local_headers = copy.deepcopy(scanner.http_headers)
        fake_ip(scanner, local_headers)
        fake_session_id(scanner, local_headers)

        query_dict = copy.deepcopy(scanner.query_dict)
        body_dict = copy.deepcopy(scanner.body_dict)
        query = copy.deepcopy(scanner.query)
        body = copy.deepcopy(scanner.body)
        params_dict = query_dict if scanner.args.get else body_dict    # temp dict

        if scanner.args.auth:
            # replace placeholder
            for _ in ['{user}', '{username}', '{user_name}', '{admin_name}']:
                if _ in param_values[1]:
                    param_values[1] = param_values[1].replace(_, param_values[0])
            # apply hash func
            for i in range(2):
                if i in scanner.selected_params:
                    param_values[i] = scanner.selected_params[i](param_values, i)
            #
            if scanner.auth_mode == 'Basic':
                auth = HTTPBasicAuth(param_values[0], param_values[1])
            elif scanner.auth_mode == 'NTLM':
                auth = HttpNtlmAuth(param_values[0], param_values[1])
            elif scanner.auth_mode == 'Digest':
                auth = HTTPDigestAuth(param_values[0], param_values[1])
            #
            data_to_print = ' '.join(param_values)
        elif scanner.args.check_proxy:
            pass
        else:
            param_values = param_values.split('^^^')  # e.g. param_values = ['test', '{user}123456']
            i = 0
            if scanner.inject_tag_count:
                # apply functions
                for p, v in scanner.selected_params.items():
                    if 'func' in v:
                        param_values[int(p)-1] = v['func'](param_values, int(p)-1)

                if scanner.args.get:
                    for _index in range(scanner.inject_tag_count):
                        query = query.replace('{PARAM_VALUE_%s}' % _index, param_values[_index])
                    data_to_print = query if len(query) < 40 else ', '.join(param_values)
                else:
                    for _index in range(scanner.inject_tag_count):
                        body = body.replace('{PARAM_VALUE_%s}' % _index, param_values[_index])
                    data_to_print = body if len(body) < 40 else ', '.join(param_values)
            else:
                # replace value
                for param_name in scanner.selected_params.keys():
                    params_dict[param_name] = param_values[i]
                    i += 1

                # replace placeholder like {user} to its value
                for p in scanner.selected_params:
                    for p2 in params_dict:
                        params_dict[p] = params_dict[p].replace('{%s}' % p2, params_dict[p2])

                # apply functions
                for p, v in scanner.selected_params.items():
                    if 'func' in v:
                        params_dict[p] = v['func'](params_dict, p)

                # only print select params and values, need unquote
                data_to_print = dict((k, v) for k, v in params_dict.items() if k in scanner.selected_params)
                data_to_print = urlencode(data_to_print)
                data_to_print = unquote(data_to_print)

        if not scanner.args.silent and not scanner.args.check_proxy and not (auth_schema_test or request_test):
            scanner.print_s('[+] Test with:  %s' % data_to_print)

        max_retries = 1 if scanner.args.check_proxy else 3
        retry_count = 0
        while retry_count < max_retries:
            url = '%s://%s' % (scanner.scm, scanner.netloc)
            if not scanner.path:
                scanner.path = '/'
            url += scanner.path
            if not scanner.args.get:
                url += '?' + scanner.query    # stay unchanged

            try:
                proxies = None
                if scanner.proxy_on:
                    cur_proxy = get_proxy(scanner)
                    proxies = {'http': cur_proxy, 'https': cur_proxy}
                    if scanner.args.check_proxy:
                        scanner.print_s('[+] Check proxy server %s' % cur_proxy)

                if scanner.args.get:
                    r = requests.get(url=url, params=query if scanner.inject_tag_count else params_dict,
                                     headers=local_headers,
                                     allow_redirects=scanner.args.allow_redirect,
                                     proxies=proxies, auth=auth, verify=False, timeout=40)
                else:
                    r = requests.post(url=url, data=body if scanner.inject_tag_count else params_dict,
                                      headers=local_headers,
                                      allow_redirects=scanner.args.allow_redirect,
                                      proxies=proxies, auth=auth, verify=False, timeout=40)
                local_request_count += 1
                if scanner.args.debug:
                    scanner.print_s('[ HTTP Request And Response ]', color='title')
                    scanner.print_s('\n{}\r\n{}\r\n\r\n'.format(
                        r.request.method + ' ' + r.request.url,
                        '\r\n'.join('{}: {}'.format(k, v) for k, v in r.request.headers.items())
                        ))
                    if r.request.body:
                        scanner.print_s(r.request.body)

                res_headers = '\r\n'.join('{}: {}'.format(k, v) for k, v in r.headers.items())
                if auth_schema_test:
                    supported_schemas = []
                    for k, v in r.headers.items():
                        if k.lower() == 'www-authenticate':
                            v = v.lower()
                            if 'basic' in v:
                                supported_schemas.append('Basic')
                            if 'digest' in v:
                                supported_schemas.append('Digest')
                            if 'ntlm' in v:
                                supported_schemas.append('NTLM')
                    count = len(supported_schemas)
                    if count < 1:
                        scanner.print_s('No supported auth schema found, '
                                        'only support: Basic/Digest/NTLM', color='warning')
                        scanner.STOP_ME = True
                        exit(-1)
                    elif count == 1:
                        scanner.print_s('[+] Auth schema is: %s' % supported_schemas[0], color='info')
                        scanner.auth_mode = supported_schemas[0]
                    elif count > 1:
                        while True:
                            scanner.print_s('Multiple auth schemas supported, enter number to choose one: ',
                                            color='info')
                            for _ in range(count):
                                scanner.print_s('[%s] %s' % (_, supported_schemas[_]), color='info')
                            choice = input('Enter Number[0-%s]: ' % (count - 1))
                            if choice.isdigit() and 0 <= int(choice) <= count-1:
                                scanner.auth_mode = supported_schemas[int(choice)]
                                scanner.print_s('')
                                break
                            else:
                                scanner.print_s('Input error, try again', color='warning')

                request_test_return_302 = False
                if request_test and r.status_code == 302 and not scanner.args.no302 and \
                        not scanner.args.header_fail and not scanner.args.header_success:
                    scanner.print_s('\n[Warning] Init request return status 302, but --no302 is off', color='warning')
                    scanner.print_s('Must set --header-success or --header-fail to check response', color='warning')
                    request_test_return_302 = True

                r.encoding = 'utf-8'
                html_doc = r.text

                html_doc = html_doc.replace('\r', r'\r').replace('\n', r'\n').replace('\t', ' ')
                html_doc = re.sub(' +', ' ', html_doc)  # Leave one blank only

                if scanner.args.debug and (not request_test or request_test_return_302):
                    scanner.lock.acquire()
                    print('')
                    print('HTTP/1.1', r.status_code, r.reason)
                    print('\r\n'.join('{}: {}'.format(k, v) for k, v in r.headers.items()))
                    print('')
                    print(html_doc)
                    print('\n' + '*' * CONSOLE_WIDTH)
                    scanner.lock.release()

                if scanner.args.retry_txt and html_doc.find(scanner.args.retry_txt) >= 0:
                    raise Exception('Retry for <%s>' % scanner.args.retry_txt)

                if scanner.args.retry_no_txt and html_doc.find(scanner.args.retry_no_txt) < 0:
                    raise Exception('Retry for no <%s>' % scanner.args.retry_no_txt)

                if scanner.args.retry_header and res_headers.find(scanner.args.retry_header) >= 0:
                    raise Exception('Retry for header <%s>' % scanner.args.retry_header)

                if scanner.args.retry_no_header and res_headers.find(scanner.args.retry_no_header) < 0:
                    raise Exception('Retry for no header <%s>' % scanner.args.retry_no_header)

                if scanner.args.check_proxy and \
                        html_doc.find('First line of request did not contain an absolute URL') > 0:
                    scanner.print_s('Proxy error, need enable invisible proxy support', color='error')

                found_err_tag = False
                for tag in scanner.args.fail:
                    if html_doc.find(tag) >= 0:
                        found_err_tag = True

                found_suc_tag = False
                suc_tag_matched = ''
                for tag in scanner.args.suc:
                    if html_doc.find(tag) >= 0:
                        suc_tag_matched += tag + ' '
                        found_suc_tag = True
                suc_tag_matched = suc_tag_matched.strip()

                cracked_msg = ''
                if not scanner.args.no302 and r.status_code == 302:
                    cracked_msg = '[+]%s \t\t{302 redirect}' % data_to_print

                if r.status_code == 200 and scanner.args.fail and not found_err_tag:
                    cracked_msg = '[+]%s \t\t{%s not found}' % (data_to_print, scanner.args.fail)

                if scanner.args.suc and found_suc_tag:
                    cracked_msg = '[+]%s \t\t[Found %s]' % (data_to_print, suc_tag_matched)

                if scanner.args.header_fail:
                    if res_headers.find(scanner.args.header_fail) < 0:
                        cracked_msg = '[+]%s \t\t[%s not found in headers]' % (data_to_print, scanner.args.header_fail)
                    else:
                        cracked_msg = ''

                if scanner.args.header_success:
                    if res_headers.find(scanner.args.header_success) >= 0:
                        cracked_msg = '[+]%s \t\t[Found %s in headers]' % (data_to_print, scanner.args.header_success)
                    else:
                        cracked_msg = ''

                if scanner.args.auth and r.status_code != 401:
                    cracked_msg = '[+][%s Auth] %s %s %s' % (
                        scanner.auth_mode, scanner.args.u, ' '.join(param_values), '[status %s]' % r.status_code)

                if cracked_msg:
                    if request_test:
                        scanner.print_s('[ERROR] Init request return success, reason is: %s' %
                                        cracked_msg.split('\t\t')[-1], color='error')
                        scanner.print_s('%s' % cracked_msg, color='warning')
                        scanner.STOP_ME = True
                        import sys
                        sys.exit(-1)
                    else:
                        add_cracked_count(scanner)
                        if scanner.args.check_proxy:
                            scanner.print_s('[OK] %s' % cur_proxy, color='success')
                            with open(scanner.args.o, 'a') as outFile:
                                outFile.write(cur_proxy + '\n')
                        else:
                            scanner.print_s('[SUCCESS] %s' % data_to_print, color='success')
                            with open(scanner.args.o, 'a') as outFile:
                                outFile.write(cracked_msg + '\n')

                if retry_count == max_retries:
                    scanner.queue.put(origin_param_values)  # put in queue again

                if scanner.args.sleep:
                    time.sleep(float(scanner.args.sleep))

                if auth_schema_test:
                    return
                if request_test:
                    return
                break

            except Exception as e:
                retry_count += 1
                if not scanner.args.check_proxy:
                    scanner.print_s('[do_request.exception] %s' % e)
                time.sleep(0.1)

        scanner.queue.task_done()
