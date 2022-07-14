# −*− coding: UTF−8 −*−

from setuptools import setup, Extension

PATH_ALG = 'src/algorithms/'
PATH_WPS = 'src/wrappers/'

snowv = Extension('snowv', 
                  sources=[
                            PATH_WPS+'pysnowv.c',
                            PATH_ALG+'snowv.c',
                            PATH_ALG+'snowv-gcm.c',
                            PATH_ALG+'ghash.c'
                          ]
                 )

pysnow = Extension('pysnow',
                    sources=[
                              PATH_WPS+'pysnow.c',
                              PATH_ALG+'SNOW_3G.c'
                            ]
                  )

pyzuc = Extension('pyzuc',
                  sources=[
                            PATH_WPS+'pyzuc.c', 
                            PATH_ALG+'ZUC.c'
                          ]
                )

with open('requirements.txt', 'r') as file:
  requirements = file.readlines()

setup(
    name='pycrypto5G',
    version='0.1',
    author='Jhonatan Cléto',
    description='5G Cryptographic reference algorithms python bindings',
    license='GPLv2+',
    packages=['Cyphers'],
    ext_modules=[snowv, pysnow, pyzuc],
    install_requires=requirements, 
)