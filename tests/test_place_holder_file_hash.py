import os
import sys

"""
python htpwdScan.py -f login_request_place_holder.txt -d 1=user.txt 2=md5(passwd.txt) --header-fail login_error
"""

if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0],
                '-f', 'login_request_place_holder.txt',
                '-d', '1=user.txt', '2=md5(passwd.txt)',
                '--header-fail', 'login_error', '--proxy', '127.0.0.1:8080']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()


