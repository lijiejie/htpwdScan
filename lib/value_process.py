#!/usr/bin/env python
# encoding=utf-8
#
# process param value
#

import hashlib


def md5(param_values, index):
    return hashlib.md5(param_values[index].encode()).hexdigest()


def md5_16(param_values, index):
    return hashlib.md5(param_values[index].encode()).hexdigest()[8:24]


def sha1(param_values, index):
    return hashlib.sha1(param_values[index].encode()).hexdigest()


def capitalize(param_values, index):
    return param_values[index].capitalize()


# add your function here
def my_own_func(param_values, index):
    return param_values[index]
