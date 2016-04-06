all: window

.PHONY: clean

window: window.c
	${CC} -Wall -pedantic $^ -o $@

clean:
	rm -f window

