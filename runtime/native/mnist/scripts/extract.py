# run in host, under shared folder

import re
import numpy as np

profiler_num = 8
state = 0
remained = profiler_num

hash_table = {}

with open('./metrics') as f:
    for line in f:
        if state==0:
            m = re.match("Profiler", line)
            if m!=None:
                state = 1
        else:
            if remained>0:
                remained-=1
                m = re.search(r"([a-zA-Z ]+)([0-9]+\.[0-9]+) ms \(raw data: [0-9]+ s, [0-9]+ ns\)", line)
                key = m.group(1).strip()
                value = m.group(2)
                
                if hash_table.get(key)==None:
                    hash_table[key] = []
                hash_table[key].append(float(value))

            else:
                remained = profiler_num
                state = 0

for k,v in hash_table.items():
    lst = v

    mean = np.mean(lst)
    std = np.std(lst, ddof=0)
    cv = std/mean
    print("{} mean: {:.2f}, std: {:.2f}, cv: {:.2f}".format(k, mean, std, cv))


