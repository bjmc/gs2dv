# Copyright (c) 2010 Media Temple, Inc.


# setuptools is better for developers so they can do 'python setup.py --develop'
# and run the program without installing it in the Python system directory
try:
    from setuptools import setup
except:
    print "Warning, no setuptools!"
    from distutils.core import setup

from gs2dvlib.__init__ import __version__ as VERSION



setup(name='gs2dv',
    license = "GPL-2",
    version=VERSION,
    description='Media Temple (gs) to (dv) migration script',
    long_description=open("README", "r").read(),
    maintainer="Brendan McCollam",
    author="Brendan McCollam",
    author_email="someone@mediatemple.net",
    url="http://github.org/cakebread/gs2dv",
    keywords="mt gs grid dv media temple",
    classifiers=["Development Status :: 3 - Alpha",
                 "Intended Audience :: Developers",
                 "License :: OSI Approved :: GNU General Public License (GPL)",
                 "Programming Language :: Python",
                 "Topic :: Software Development :: Libraries :: Python Modules",
                 ],
    install_requires=["setuptools"],
    tests_require=["nose"],
    packages=['gs2dvlib'],
    package_dir={'gs2dvlib':'gs2dvlib'},
    entry_points={'console_scripts': ['gs2dv = gs2dvlib.cli:main',]},
    test_suite = 'nose.collector',
)

