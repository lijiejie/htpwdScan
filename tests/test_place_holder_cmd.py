import os
import sys

"""
  python htpwdScan.py -u "http://127.0.0.1:8000/task/get_brute?key=$$$123451$$$&user=$$$111$$$" 
  -d 1=pass.txt 2=user.txt --get --fail FAIL
"""

if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, '..'))
    from htpwdScan import Scanner
    sys.argv = [sys.argv[0],
                '-u', 'http://127.0.0.1:8000/task/get_brute?key=$$$123451$$$&user=$$$111$$$',
                '-d', '1=passwd.txt', '2=user.txt',
                '--get',
                '--fail', 'FAIL']
    print('Run: %s' % ' '.join(sys.argv))
    s = Scanner()
    s.run()


