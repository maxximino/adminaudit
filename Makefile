.PHONY: install
CXXFLAGS = -fPIC -std=c++0x -O2 -g -DDBUG_OFF -DMYSQL_DYNAMIC_PLUGIN -Dadminaudit_EXPORTS $(shell mysql_config --cflags) -Werror
LDFLAGS = -lpthread -shared -lboost_thread
adminaudit.so: adminaudit.cpp adminaudit.hpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -Wl,-soname,adminaudit.so -o adminaudit.so adminaudit.cpp

install: adminaudit.so
	mkdir -p $(DESTPREFIX)$(shell mysql_config --plugindir)
	cp adminaudit.so $(DESTPREFIX)$(shell mysql_config --plugindir)/
