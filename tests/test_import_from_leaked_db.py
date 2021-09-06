import os
import sys


if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0], '-f', 'login_request.txt', '--database', 'login,passwd=leaked_db.txt',
                '--regex', r'(\S+)\s+(\S+)',
                '--header-fail', 'login_error=Bad+user+name+or+password']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()
