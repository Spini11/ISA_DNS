debug:
	g++ -g -Wall -std=c++2a -static-libstdc++ ./dns.cpp ./arguments.cpp ./errorHandling.cpp ./main.cpp ./output.cpp -o dns

test:
	g++ -g -Wall -std=c++2a -static-libstdc++ ./dns.cpp ./arguments.cpp ./errorHandling.cpp ./test/main.cpp ./test/ArgumentParserTest/ArgParsTest.cpp ./test/QueryCreateTest/QueryCreateTest.cpp ./test/ReadQueryTest/ReadQueryTest.cpp ./test/CompleteTest.cpp ./output.cpp -o dnsTest
	./dnsTest

.PHONY: test

