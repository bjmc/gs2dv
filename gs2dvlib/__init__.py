#!/usr/bin/env python
# Copyright (c) 2010 Media Temple, Inc.

import sys
import optparse

import meta

__version__ = '0.1'

def main(prog_args):
    parser = optparse.OptionParser(version=meta.__version__)
    opt, args = parser.parse_args(prog_args)

if __name__ == '__main__':
    sys.exit(main(sys.argv))

