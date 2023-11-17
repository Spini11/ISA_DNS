CC=g++
CFLAGS=-Wall -std=c++2a -static-libstdc++
DEPS = dns.cpp arguments.cpp errorHandling.cpp output.cpp main.cpp
DEPS_TEST = dns.cpp arguments.cpp errorHandling.cpp output.cpp test/main.cpp test/ArgumentParserTest/ArgParsTest.cpp test/QueryCreateTest/QueryCreateTest.cpp test/ReadQueryTest/ReadQueryTest.cpp test/CompleteTest.cpp

dns: $(DEPS)
	$(CC) $(CFLAGS) $(DEPS) -o dns

debug: $(DEPS)
	$(CC) -g $(CFLAGS) $(DEPS) -o dns

test: $(DEPS_TEST)
	$(CC) -g $(CFLAGS) $(DEPS_TEST) -o dnsTest
	./dnsTest

clean:
	rm -f dns dnsTest

.PHONY: all

