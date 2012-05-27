from distutils.core import setup
import fileinput

setup (
    name='pyocb',
    author='Pawel Krawczyk',
    author_email='pawel.krawczyk@hush.com',
    url='http://ipsec.pl/pyocb',
    version='1.0',
    packages=['ocb', ],
    description='OCB-AES authenticated encryption for Python',
    long_description=fileinput.input('README.md'),
    license="Public domain",
    classifiers=[
                 'Development Status :: 4 - Beta',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                 'Topic :: Security :: Cryptography',
                 'Programming Language :: Python',
                 'Topic :: Software Development :: Libraries',
                 ],
       )
