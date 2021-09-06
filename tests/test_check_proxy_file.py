import os
import sys


if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0], '--proxy-file', 'proxies.txt', '--check-proxy', '-u',
                'https://www.baidu.com', '--suc', '/content-search.xml', '--get']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()


