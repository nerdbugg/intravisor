REMOTE_TARGET := root@cheribsd:/intravisor

all :
	@$(MAKE) -C src

sync:
	scp $$(git diff --name-only  | cat | xargs printf '%s ') ${REMOTE_TARGET}/monitor_src/
	scp src/build/monitor ${REMOTE_TARGET}/monitor_dev 

.PHONY: all clean sync
