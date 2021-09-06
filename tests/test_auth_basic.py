import os
import sys


if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0], '-u', 'https://jigsaw.w3.org/HTTP/Basic/', '--auth', 'user.txt', 'passwd.txt']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()


