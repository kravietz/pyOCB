from distutils.core import setup

f = open('README.md')
desc = f.read()

setup (
    name='pyocb',
    author='Pawel Krawczyk',
    author_email='pawel.krawczyk@hush.com',
    url='http://pypi.python.org/pypi/pyocb',
    version='1.2',
    packages=['ocb', ],
    description='OCB-AES authenticated encryption for Python',
    long_description=desc,
    license="GNU General Public License v3 or later (GPLv3+)",
    classifiers=[
                 'Development Status :: 4 - Beta',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                 'Topic :: Security :: Cryptography',
                 'Programming Language :: Python',
                 'Topic :: Software Development :: Libraries',
                 ],
       )
