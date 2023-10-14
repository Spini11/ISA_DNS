CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -pedantic -O2

SRCS = arguments.cpp main.cpp dns.cpp
OBJS = $(SRCS:.cpp=.o)

TARGET = dns

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

debug: $(OBJS)
	$(CXX) $(CXXFLAGS) -g $(OBJS) -o $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

