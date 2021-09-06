#!/usr/bin/env python
#
# Parse HTTP request from file or from command line
#

from urllib.parse import urlparse, parse_qsl
import re
import os


def parse_command_line_url(scanner):
    if not scanner.args.u.lower().startswith('http'):
        scanner.args.u = 'http://%s' % scanner.args.u
    (scanner.scm, scanner.netloc, scanner.path, _params, scanner.query, _fragment) = \
        urlparse(scanner.args.u, 'http')
    scanner.query_dict = dict(parse_qsl(scanner.query))
    scanner.inject_tag_count = count = scanner.query.count('$$$')
    if count > 0:
        if count >= 2 and count % 2 == 0:
            scanner.inject_tag_count = int(count/2)
            scanner.print_s('[+] Inject tags found, tag count is %s' % scanner.inject_tag_count, color='warning')
            _index = 0
            while scanner.query.count('$$$') > 0:
                scanner.query = re.sub(r'\$\$\$.*?\$\$\$', '{PARAM_VALUE_%s}' % _index, scanner.query, count=1)
                _index += 1
        else:
            scanner.print_s('[ERROR] Inject tag must be set by pair: $$$value$$$', color='error')
            import sys
            sys.exit(-1)
    scanner.body = ''
    scanner.body_dict = {}


def parse_request(scanner):
    scanner.http_headers = {
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
    }

    if scanner.args.u:
        parse_command_line_url(scanner)
        return

    # Load HTTP request from file
    if not os.path.exists(scanner.args.f):
        raise Exception('Request file not found')

    scanner.scm = 'https' if scanner.args.https else 'http'

    with open(scanner.args.f) as f:
        post_text = f.read()
    lines = post_text.split('\n')

    first_line = lines[0].strip()
    scanner.args.get = True if first_line.upper().startswith('GET') else False
    scanner.netloc = re.search('Host: (.*)', post_text).group(1).strip()

    scanner.path = first_line.split(' ')[1]
    if scanner.path.find('://') > 0:    # absolute URL
        scanner.path = scanner.path.replace('://', '')
        scanner.path = scanner.path[scanner.path.find('/'):].strip()

    (_, _, scanner.path, _, scanner.query, _) = urlparse(scanner.path)
    scanner.query_dict = dict(parse_qsl(scanner.query))
    scanner.body = ''
    scanner.body_dict = {}
    if not scanner.args.get:
        for i in range(len(lines)-1, 0, -1):
            body = lines[i].strip()
            if body:
                scanner.body_dict = dict(parse_qsl(body))
                scanner.inject_tag_count = count = body.count('$$$')
                if count > 0:
                    if count >= 2 and count % 2 == 0:
                        scanner.inject_tag_count = int(count/2)
                        scanner.print_s('[+] Inject tags found, tag count is %s' % scanner.inject_tag_count,
                                        color='warning')
                        _index = 0
                        while body.count('$$$') > 0:
                            body = re.sub(r'\$\$\$.*?\$\$\$', '{PARAM_VALUE_%s}' % _index, body, count=1)
                            _index += 1
                        scanner.body = body
                    else:
                        scanner.print_s('[ERROR] Inject tag must be set by pair: ^^^value^^^', color='error')
                        import sys
                        sys.exit(-1)
                break

    # deal with headers
    keys = ['User-Agent', 'Cookie', 'Origin', 'Referer',
            'Client-IP', 'X-Forwarded-For', 'X-Forwarded-Host',
            'Via', 'Content-Type', 'Accept-Language',
            'Authorization', 'X-Requested-With', 'Accept-Encoding']
    for k in keys:
        m = re.search('%s: (.*)' % k, post_text)
        if m:
            scanner.http_headers[k] = m.group(1).strip()
