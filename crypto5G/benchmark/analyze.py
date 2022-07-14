import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

crypto_bench_df = pd.read_csv('benchmark/crypto_bench.csv', index_col=0)

df = crypto_bench_df.reset_index()

df_melt = crypto_bench_df.reset_index().melt('index', var_name='bytes', value_name='vals')
df_melt['bytes'] = df_melt['bytes'].str.replace('bytes', '')
df_melt['bytes'] = df_melt['bytes'].astype('int')

g = sns.catplot(data = df_melt, x='bytes', y='vals',
                hue='index', aspect=16/9, legend=True)
g.set_xlabels("Tamanho da entrada (bytes)", fontsize=13)
g.set_ylabels('Tempo (s)', fontsize=13)
g.ax.set_title(r'Tamanho da entrada $\times$ Tempo de encriptação dos Cifradores do 5G', fontsize=14)
g.ax.legend(title='Cifrador')

g.savefig('benchmark/fig.png')
