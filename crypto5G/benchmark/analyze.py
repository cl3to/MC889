import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

crypto_bench_df = pd.read_csv('benchmark/crypto_bench.csv', index_col=0)

# Visual Benchmark

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

# Percentual Benchmark

aes_row = crypto_bench_df.iloc[0]
df2 = round((aes_row/crypto_bench_df), 2)

df_melt = df2.reset_index().melt('index', var_name='bytes', value_name='vals')
df_melt['bytes'] = df_melt['bytes'].str.replace('bytes', '')
df_melt['bytes'] = df_melt['bytes'].astype('int')

#print(df_melt)

plt.figure(figsize=(14, 9))
ax = sns.barplot(x="bytes", y="vals", hue="index", data=df_melt)
ax.set_xlabel('Tamanho da mensagem (Bytes)', fontsize=14)
ax.set_ylabel('Desempenho relativo ao AES', fontsize=14)
ax.legend(title='Cifrador', fontsize=14, title_fontsize=14)

ax.axhline(y=1, color='black', linestyle='--')
ax.text(s="Baseline", x=6, y=1.2, fontsize=12)

plt.savefig("benchmark/fig2.png")