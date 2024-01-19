#! /bin/env python3
# run in host, under shared folder

import re
import numpy as np

profiler_num = 8
state = 0
remained = profiler_num

metrics_lst = []

with open('./metrics') as f:
    cur_profiler_group_name = ""
    metric_point = {}
    for line in f:
        # print('"{}"'.format(line.strip()))

        if state==0:
            if cur_profiler_group_name != "":
                # print('save')
                metrics_lst.append(metric_point)
                metric_point = {}
                cur_profiler_group_name = ""

            m = re.match(">>>>>--------------------", line)
            if m==None:
                continue
            # print('0->1')
            state = 1
        elif state==1:
            m = re.match("Profiler name: <(?P<name>[a-z ]+)>", line)
            if m==None:
                continue
            cur_profiler_group_name = m.group('name')
            # print('1->2')
            state = 2
        elif state==2:
            m = re.match("Profiler analysis:", line)
            if m==None:
                continue
            # print('2->3')
            state = 3
        elif state==3:
            m = re.search(r"([a-zA-Z ]+)([0-9]+\.[0-9]+) ms \(raw data: [0-9]+ s, [0-9]+ ns\)", line)
            if m==None:
                # print('3->4')
                state = 4

                m = re.match("<<<<<--------------------", line)
                if m!=None:
                    # print('4->0')
                    state = 0

                continue

            key = m.group(1).strip()
            value = m.group(2)

            if metric_point.get(key)!=None:
                print("duplicate point in a single metric point!")
            metric_point[key]=float(value)

        elif state==4:
            m = re.match("<<<<<--------------------", line)
            if m==None:
                continue
            # print('4->0')
            state = 0

metrics_map = {}
for obj in metrics_lst:
    for k,v in obj.items():
        if metrics_map.get(k)==None:
            metrics_map[k] = []
        metrics_map[k].append(v)

# print(metrics_map)

for k,v in metrics_map.items():
    lst = v

    mean = np.mean(lst)
    std = np.std(lst, ddof=0)
    cv = std/mean
    print("{} mean: {:.2f}, std: {:.2f}, cv: {:.2f}".format(k, mean, std, cv))


