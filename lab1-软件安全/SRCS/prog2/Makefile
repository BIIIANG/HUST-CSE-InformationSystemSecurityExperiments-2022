all: 
	gcc -m32 -z noexecstack -fstack-protector -o prog2 prog2.c
	sudo chown root prog2
	sudo chmod 4755 prog2

check:
	checksec --file=prog2
	
clean: 
	rm -f prog2