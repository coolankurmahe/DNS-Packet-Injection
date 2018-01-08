all: dnsinject dnsdetect

dnsinject: dnsinject.c
	gcc -w dnsinject.c -o dnsinject -lpcap

dnsdetect: dnsdetect.c
	gcc -w dnsdetect.c -o dnsdetect -lpcap

clean:
	rm -f dnsinject
	rm -f dnsdetect
