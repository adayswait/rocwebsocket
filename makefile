allobj = roc_websocket.o base64.o sha1.o
all:roc_interface.h roc_interface.cc roc_websocket.h roc_websocket.cc $(allobj)
	g++ -fPIC -shared -o websocket.so -std=c++11 roc_interface.cc $(allobj)
roc_websocket.o:roc_websocket.h roc_websocket.cc
	g++ -c -std=c++11 -fPIC roc_websocket.cc
base64.o:base64.h base64.cc
	g++ -c -std=c++11 -fPIC base64.cc
sha1.o:sha1.h sha1.cc
	g++ -c -std=c++11 -fPIC sha1.cc
