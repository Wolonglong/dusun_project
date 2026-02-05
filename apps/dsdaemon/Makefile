
objects := $(patsubst %.c,%.o,$(wildcard *.c))
INC_DIRS := -I. -I../include
LINK_DIRS := -L../root/lib


all: $(objects)
	$(COMPILER) -o dsdaemon $(objects) -L. $(LINK_DIRS) -luci -lubus -lubox 

%.o: %.c
	$(COMPILER) -O2 -fPIC -c $(INC_DIRS) -o $@ $<
clean:
	rm ./*.o
	rm ./dsdaemon

install:
	cp ./dsdaemon ../root/usr/bin/
	ln -s /usr/bin/dsdaemon   ../root/usr/bin/ds_sethwmac
	cp ./S99dsdaemon ../root/etc/init.d/

