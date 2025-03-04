.PHONY: default
default:
	@echo "targets:"
	@echo "  - linux_64"
	@echo "  - windows_64"

.PHONY: linux_64
linux_64:
	gcc -Wall -Werror -shared -o linux_64/libgmpwrapper.so -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" gmpwrapper.c ./linux_64/libgmp.a

.PHONY: windows_64
windows_64:
	gcc.exe -Wall -Werror -shared -o windows_64/gmpwrapper.dll -I"${JAVA_HOME}include" -I"${JAVA_HOME}include\win32" gmpwrapper.c ./windows_64/gmp.lib