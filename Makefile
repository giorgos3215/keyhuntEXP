CXX = g++
CXXFLAGS = -I. -Isecp256k1 -Ihash -Ioldbloom -Ibloom -Ibase58 -Irmd160 -Isha3 -Ixxhash -march=native -mtune=native -Wall -Wextra -Ofast -ftree-vectorize
LDFLAGS = -lm -lpthread -lcrypto -lgmp

all: keyhunt

keyhunt: keyhunt_unified.cpp
	$(CXX) $(CXXFLAGS) -o keyhunt keyhunt_unified.cpp $(LDFLAGS)

clean:
	rm -f keyhunt *.o
