.PHONY: default
default: linux

.PHONY: linux
linux:
	cc -Wall -Werror -shared -o libgmpwrapper.so -fPIC -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" gmpwrapper.c -lgmp
	
