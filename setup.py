#!/usr/bin/env python
# coding: UTF-8

from setuptools import find_packages, setup

with open('README.md') as fp:
    readme = fp.read()

setup(
        name='libcgroup',
        version='0.1.0',
        author='Byeonghoon Yoo',
        author_email='bh322yoo@gmail.com',
        description='A library that handles Linux cgroups internally using the libcgroup shared library.',
        long_description=readme,
        long_description_content_type='text/markdown',
        url='https://github.com/isac322/python-libcgroup',
        packages=find_packages(exclude=('test',)),
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: No Input/Output (Daemon)',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
            'Natural Language :: English',
            'Operating System :: POSIX :: Linux',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3 :: Only',
            'Programming Language :: Python :: Implementation',
            'Programming Language :: Python :: Implementation :: CPython',
            'Programming Language :: Python :: Implementation :: PyPy',
            'Programming Language :: Python :: Implementation :: Stackless',
            'Topic :: Software Development',
            'Topic :: Software Development :: Embedded Systems',
            'Topic :: Software Development :: Libraries',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: System',
            'Topic :: System :: Filesystems',
            'Topic :: System :: Operating System',
            'Topic :: System :: Operating System Kernels',
            'Topic :: System :: Operating System Kernels :: Linux',
            'Typing :: Typed',
        ],
        license='LGPLv3+',
        keywords='Linux cgroup libcgroup control_group',
        python_requires='>=3.6',
        provides=['libcgroup'],
        platforms='Linux',
        install_requires=[
            'libcgroup_bind'
        ],
        extras_require={
            'stub': ['typing']
        }
)
