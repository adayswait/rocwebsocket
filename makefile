all:plugin.h plugin.cc rocws.o base64.o sha1.o
	g++ -std=c++11 plugin.cc rocws.o base64.o sha1.o -fPIC -shared -o websocket.so
rocws.o:rocws.h rocws.cc
	g++ -c -std=c++11 -fPIC rocws.cc
base64.o:base64.h base64.cc
	g++ -c -std=c++11 -fPIC base64.cc
sha1.o:sha1.h sha1.cc
	g++ -c -std=c++11 -fPIC sha1.cc
