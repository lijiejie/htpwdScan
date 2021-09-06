import os
import sys


if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0], '-f', 'login_request.txt', '-d', 'login=user.txt', 'passwd=md5(passwd.txt)',
                '--header-fail', 'login_error=Bad+user+name+or+password']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()
