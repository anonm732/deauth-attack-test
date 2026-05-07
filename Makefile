CXX = g++
CXXFLAGS = -Wall -O2

TARGET = deauth-attack-test

SRC = main.cpp mac.cpp radiotap.cpp dot11.cpp deauth.cpp util.cpp pch.cpp
OBJ = $(SRC:.cpp=.o)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) -lpcap

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(TARGET) $(OBJ)