CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -pthread
LDFLAGS  ?= -pthread

TARGET = fragtunnel
SRC    = fragtunnel.cpp

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

debug: CXXFLAGS = -std=c++17 -O0 -g -Wall -Wextra -pthread -fsanitize=address,undefined
debug: LDFLAGS  = -pthread -fsanitize=address,undefined
debug: clean $(TARGET)

clean:
	rm -f $(TARGET)
