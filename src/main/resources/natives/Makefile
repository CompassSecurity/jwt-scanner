.PHONY: default
default:
	@echo "targets:"
	@echo "  - linux_64"

.PHONY: linux_64
linux_64:
	cc -Wall -Werror -shared -o linux_64/libgmpwrapper.so -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" -lgmp gmpwrapper.c
	
