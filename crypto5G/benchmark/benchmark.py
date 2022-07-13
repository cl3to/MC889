from functions import *
import timeit
import time
import numpy as np
import pandas as pd

funcs = (aes_enc, zuc_enc, snow3g_enc, snowv_enc)
sizes = (size_64, size_256, size_1024, size_2048, size_4096, size_8192, size_16384)
func_str = "{}(d_size)"

results = list()

for func in funcs:
    f_results = list()
    for size in sizes:
        print(func.__name__, size)
        times = timeit.repeat(stmt=func_str.format(func.__name__),
                    setup=f"d_size = {size}",
                    repeat = 100,
                    number=1,
                    globals=globals())

        time = np.array(times).mean()

        f_results.append(time)

    results.append(f_results)


crypto_bench = pd.DataFrame(data=results,
                            index=['AES', 'ZUC', 'SNOW3G', 'SNOW-V'], 
                            columns=['64 bytes', '256 bytes', '1024 bytes', '2048 bytes',
                                    '4096 bytes', '8192 bytes', '16384 bytes']
                            )

print(crypto_bench.head())

crypto_bench.to_csv('benchmark/crypto_bench.csv', encoding='utf-8')