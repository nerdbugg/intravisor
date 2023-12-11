#! /usr/bin/env bash

# run in cheribsd vm, using bash syntax

LOOP_NUM=5

if [[ -f ./metrics ]]; then
  rm ./metrics
fi

touch ./metrics

for ((i=0;i<=$LOOP_NUM;i++))
do
  ./run_experiment_single.sh >> metrics &
  sleep 2
  pkill monitor
done

