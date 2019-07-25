all: fake real

fake:
	gcc -g -D_GNU_SOURCE -shared -fPIC -o libfake.so fake.c -lpthread -lflexsc -ldl

real:
	gcc -D_GNU_SOURCE -shared -fPIC -o libreal.so real.c -ldl

test1:
	$(call flush)
	@LD_PRELOAD=./libfake.so ioping -S64M -L -s64k -W -c 10 . -q
	$(call flush)
	ioping -S64M -L -s64k -W -c 10 . -q

write1: fake
	$(call flush)
	@LD_PRELOAD=./libfake.so ioping -S64M -L -s64k -W -c 10 . -q | awk 'BEGIN{RS="";FS="\n"}{print $2}' >> write1.log
	$(call flush) 
	@ioping -S64M -L -s64k -W -c 10 . -q | awk 'BEGIN{RS="";FS="\n"}{print $2}' >> write1.log

write2: fake
	$(call flush)
	@LD_PRELOAD=./libfake.so ioping -S64M -L -s64k -W -c 600 . -q >> write2.log
	$(call flush)
	ioping -S64M -L -s64k -W -c 600 . -q >> write2.log

write3:
	$(call flush)
	@LD_PRELOAD=./libfake.so ioping -S1G -L -s64k -W -c 40 . -q | cut -d ' ' -f 5 | cut -d $'\n' -f 3
	$(call flush)
	@LD_PRELOAD=./libreal.so ioping -S1G -L -s64k -W -c 40 . -q | cut -d ' ' -f 5 | cut -d $'\n' -f 3

clean:
	$(RM) write1.log write2.log write3.log

flush = 										\
	@echo 3 | sudo tee /proc/sys/vm/drop_caches; \
	sudo blockdev --flushbufs /dev/sda1;        \
