# Algoritmos Criptográficos utilizados no sistema 5G

## Algoritmos Implementados
- AES
- ZUC
- SNOW3G
- SNOW-V

## Instalação

As implementações dos algoritmos são compativeis com o [Python](https://docs.python.org/3/) a partir da versão 3.6, recomendamos a criação de um ambiente virtual antes de instalar os módulos para instalar os módulos no ambiente virtual basta executar:

~~~bash
python3 -m venv .pycrypto5G
source .pycrypto5G/bin/activate
pip install -e .
~~~

ou

~~~bash
python3 -m venv .pycrypto5G
source .pycrypto5G/bin/activate
python3 setup.py install
~~~

## Uso

Cada algoritmo possui uma classe python associada, com isso para utiliza-los basta importar suas respectivas classes. Exemplo:

~~~python

from Cyphers.SNOWV import SNOWV
snowv = SNOWV()
...
encrypt_msg = snowv.encrypt(key, iv, plain_msg)
~~~


## Testes

Para rodas os testes é necessário ter o [pytest](https://docs.pytest.org/en/7.1.x/contents.html) instalado, se o procedimento de instalação foi executado, o pytest será instalado automaticamente. para testar basta rodar o comando:

~~~bash
pytest tests
~~~
