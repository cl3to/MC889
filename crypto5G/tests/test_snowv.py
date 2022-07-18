from Cyphers.SNOWV import SNOWV

"""
Conjunto de vetores de teste do SNOW-V
Obtidos do artigo original : https://eprint.iacr.org/2018/1143.pdf
Executar os testes com o pytest : pytest tests/test_snowv.py
"""

def test_snowv_set_1():
    snowv = SNOWV()
    key = 32*b'\0'
    iv = 16*b'\0'
    z0  = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 ea ea ea ea eb eb eb eb eb eb eb eb eb eb eb eb 55 f7 f7 c2 e8 e8 dd 4a e8 dd 4a e8 dd 4a e8 e8 c7 2a 23 bf e8 93 73 30 23 bc 66 ec 94 d2 eb b2 a7 dd ca f3 13 87 61 02 6e ad f4 2b 54 e3 ef cf 6a 67 62 3e 6f 8a f9 79 1e cd 81 83 c5 86 8e 3a 45 10 1e 83 a2 c6 dd eb 40 86 38 2d ac fb 3b 65 3c c4 df 56 ec bf c1 06 6d ac 02 c5 0a 68 3c fe 0c cb e1 de 2e 41 af da 70 98 d5 60 19 20 06 98 53 cd 98 69 c7 78 ca de d7 db 45 9b 6f 45 8b 10 8d 94 0b e5 9f bd b1 61 c1 21 fc 29 7a 3d 0a 15 26 13 2c 14 9e af 12 cc d3 2f 35 76 f6 43 68 94 0e 75 be 09 54 18 1e f5 8a 60 a9 a9 54 3a 05 ff dc 77 a4 97 23 eb 65 6a e1 8f 28 2c f1 de 1d 00")

    z  =  bytes.fromhex("69 ca 6d af 9a e3 b7 2d b1 34 a8 5a 83 7e 41 9d ec 08 aa d3 9d 7b 0f 00 9b 60 b2 8c 53 43 00 ed 84 ab f5 94 fb 08 a7 f1 f3 a2 df 18 e6 17 68 3b 48 1f a3 78 07 9d cf 04 db 53 b5 d6 29 a9 eb 9d 03 1c 15 9d cc d0 a5 0c 4d 5d bf 51 15 d8 70 39 c0 d0 3c a1 37 0c 19 40 03 47 a0 b4 d2 e9 db e5 cb ca 60 82 14 a2 65 82 cf 68 09 16 b3 45 13 21 95 4f df 30 84 af 02 f6 a8 e2 48 1d e6 bf 82 79")

    rz0, rz = snowv.test_case(key, iv)

    assert rz0 == z0 and rz == z

def test_snowv_set_2():
    snowv = SNOWV()
    key = bytes.fromhex(32*'ff')
    iv = bytes.fromhex(16*'ff')
    z0  = bytes.fromhex("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff d3 07 d2 07 d3 07 d2 07 d3 07 2d f8 2e f8 2d f8 65 f6 62 f6 65 f6 62 f6 65 f6 62 f6 65 f6 62 f6 fe 86 fe 86 f5 2d f2 2d 31 96 d7 54 6a e8 6a e8 8b d8 8a a5 c8 29 c6 26 7c 51 37 97 bf 9a c8 7c 21 c0 4a 14 e4 1c 34 95 d0 9c 96 e5 48 60 89 81 7c ce 64 29 1a cf 8f 4a 06 ca 55 65 3f c4 93 97 0a f9 1c 75 0f d3 80 e3 48 6b ff e5 c7 bb e3 d4 89 60 89 a2 e6 f0 7c 2c 92 ed 62 ed 9d 43 61 98 ff 04 bf 72 41 c0 7f 6b 17 fd 90 c8 8a 61 bf ca 97 88 78 33 20 08 2f f6 f9 34 45 18 6e 71 bc bc 7e 17 b4 ff 42 3a 2e 2c c7 c5 0f 84 5d 9b b3 ee 32 40 8c 85 58 e0 d2 7e f5 a3 a8 d7 63 32 25 dc a2 93 73 c3 48 2b 3f 1a d3 3b b4 57 a3 0d 7f e4 72 e0 95 5b 9a 83 3a 3f db 98 68 56 35 80 b4 b0 94 9f be 85 a4 e5 35 7f bf 75 e9 86 4d 2c 7b a1")

    z  =  bytes.fromhex("30 76 09 fb 10 10 12 54 4b c1 75 e3 17 fb 25 ff 33 0d 0d e2 5a f6 aa d1 05 05 b8 9b 1e 09 a8 ec dd 46 72 cc bb 98 c7 f2 c4 e2 4a f5 27 28 36 c8 7c c7 3a 81 76 b3 9c e9 30 3b 3e 76 4e 9b e3 e7 48 f7 65 1a 7c 7e 81 3f d5 24 90 23 1e 56 f7 c1 44 e4 38 e7 77 11 a6 b0 ba fb 60 45 0c 62 d7 d9 b9 24 1d 12 44 fc b4 9d a1 e5 2b 80 13 de cd d4 86 04 ff fc 62 67 6e 70 3b 3a b8 49 cb a6 ea 09")

    rz0, rz = snowv.test_case(key, iv)

    assert rz0 == z0 and rz == z

def test_snowv_set_3():
    snowv = SNOWV()
    key = bytes.fromhex('50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 0a 1a 2a 3a 4a 5a 6a 7a 8a 9a aa ba ca da ea fa')
    iv = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
    z0  = bytes.fromhex("0a 1a 2a 3a 4a 5a 6a 7a 8a 9a aa ba ca da ea fa 66 d4 2d 92 ac 52 b6 44 63 3c c3 71 c3 91 c6 24 a2 d7 ea be 3f 04 8e 50 00 b1 7b 74 2f 34 5e 49 96 a7 34 ed fd 07 46 9d c8 f9 a2 91 fc 13 76 73 58 c8 70 73 d8 a2 a1 bd 03 e7 a1 4c c7 b7 db 89 7e 86 eb 71 d6 dc 00 99 d1 31 e3 1b 54 c5 3e f8 a8 ca ff 06 0d c0 9e 67 cc 95 62 16 17 19 8c f2 c0 99 3a 55 f3 e2 d7 8d 6a f7 e1 57 0f a1 63 02 39 8f a0 7e ab a2 73 89 94 f9 ac 3e 8e b1 ff 64 15 32 31 6a 42 5c 12 a6 39 ce 79 cb 30 43 47 1e 2e 7a 44 fd ad 23 77 5a f1 61 1c ca 5b b2 1e 95 93 69 c8 20 a9 37 d5 c8 b6 7a df 84 45 5e 13 c3 c1 0f 8d b5 fb 37 08 31 11 d1 c8 44 6e a2 ac 9e 13 ac 34 20 7b 01 b7 ab d3 57 02 a1 ed 98 9b dc 0b 15 43 a4 74 26 2c 76 a3 e2 73 57 28 4b dc 67 7b 79 91 96 cf 6b 76 27 f8 dd a1 89 bb af dc 93")

    z  =  bytes.fromhex("aa 81 ea fb 8b 86 16 ce 3e 5c e2 22 24 61 c5 0a 6a b4 48 77 56 de 4b d3 1c 90 4f 3d 97 8a fe 56 33 4f 10 dd df 2b 95 31 76 9a 71 05 0b e4 38 5f c2 b6 19 2c 7a 85 7b e8 b4 fc 28 b7 09 f0 8f 11 f2 06 49 e2 ee f2 49 80 f8 6c 4c 11 36 41 fe d2 f3 f6 fa 2b 91 95 12 06 b8 01 db 15 46 65 17 a6 33 0a dd a6 b3 5b 26 5e fd 72 2e 86 77 b4 8b fc 15 b4 41 18 de 52 d0 73 b0 ad 0f e7 59 4d 62 91")

    rz0, rz = snowv.test_case(key, iv)

    assert rz0 == z0 and rz == z  

def test_snowv_GCM_set_1():
    snowv = SNOWV()
    key = bytes.fromhex(32*'00')
    iv = bytes.fromhex(16*'00')
    aad = b''
    plaintxt = b''
    ciphertxt = b''
    mac = bytes.fromhex('02 9a 62 4c da a4 d4 6c b9 a0 ef 40 46 95 6c 9f')

    enc, mac1 = snowv.gcm_encrypt(key, iv, plaintxt, aad)
    assert enc == ciphertxt and mac1 == mac

def test_snowv_GCM_set_2():
    snowv = SNOWV()
    key = bytes.fromhex('505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa')
    iv = bytes.fromhex('0123456789abcdeffedcba9876543210')
    aad = bytes.fromhex('30313233343536373839616263646566')
    plaintxt = b''
    ciphertxt = b''
    mac = bytes.fromhex('250ec8d77a022c087adf08b65adcbb1a')

    enc, mac1 = snowv.gcm_encrypt(key, iv, plaintxt, aad)
    return enc == ciphertxt and mac1 == mac

def test_snowv_GCM_set_3():
    snowv = SNOWV()
    key = bytes.fromhex('50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 0a 1a 2a 3a 4a 5a 6a 7a 8a 9a aa ba ca da ea fa')
    iv = bytes.fromhex('01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10')
    aad = bytes.fromhex('41 41 44 20 74 65 73 74 20 76 61 6c 75 65 21')
    plaintxt = bytes.fromhex('30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 20 53 6e 6f 77 56 2d 41 45 41 44 20 6d 6f 64 65 21')
    ciphertxt = bytes.fromhex('dd 7e 01 b2 b4 24 a2 ef 82 50 27 07 e8 7a 32 c1 52 b0 d0 18 18 fd 7f 12 24 3e b5 a1 56 59 e9 1b 4c')
    mac = bytes.fromhex('90 7e a6 a5 b7 3a 51 de 74 7c 3e 9a d9 ee 02 9b')

    enc, mac1 = snowv.gcm_encrypt(key, iv, plaintxt, aad)
    assert enc == ciphertxt and mac1 == mac
