#
#  Makefile
#  KeyMgr
#
#  Keypair/Certificate manager main file, part of "an example programon using the Openssl library"
#
#  Created by Babak Karvandi on 04/06/2017.
#  Copyright (C) Geeks Dominion LLC 2017. All rights reserved.
#
#  This software is provided 'as-is', without any express or implied
#  warranty.  In no event will the authors be held liable for any damages
#  arising from the use of this software.
#
#  Permission is granted to anyone to use this software for any purpose,
#  including commercial applications, and to alter it and redistribute it
#  freely, subject to the following restrictions:
#
#  1. The origin of this software must not be misrepresented; you must not
#     claim that you wrote the original software. If you use this software
#     in a product, an acknowledgment in the product documentation would be
#     appreciated but is not required.
#
#  2. Altered source versions must be plainly marked as such, and must not be
#     misrepresented as being the original software.
#
#  3. This notice may not be removed or altered from any source distribution.
#

# 2.00  from OSSL. archive files in 1.9.10

# 2.02  cleaned up source files

# 2.03	Adding header to source files

###### Compiled on Ubuntu 16.04
## Target: x86_64-linux-gnu
## gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4)
## ##########################################################

VERSION    = 2.04
SERVER     = KeyMgr
EXECUTABLE = $(SERVER)-$(VERSION)

PID=$(shell ps -ef | grep "$(SERVER)" | grep -v grep | awk '{print $$2}')

# C++ Compiler
CPP = g++

# c++17: enables the newer compiler feature
CPPFLAGS = -c -std=c++17

# -lcurses: NCurses library for terminal (console) handling 
# -s: strippes
# -g: to create Debug Content for gdb
LPPFLAGS  = -lcrypto -s -lcurses

.DEFAULT_GOAL := $(EXECUTABLE)

all :  $(EXECUTABLE)

$(EXECUTABLE) :  $(SERVER).o Auxiliary.o SysLog.o Secure.o
	$(CPP) $(SERVER).o Auxiliary.o SysLog.o Secure.o -o $(EXECUTABLE) $(LPPFLAGS)
	@ln -sf $(EXECUTABLE) $(SERVER)

$(SERVER).o : $(SERVER).cpp $(SERVER).h
	$(CPP) -DVERSION=\"$(VERSION)\" -DSERVERNAME='"$(SERVER)"' $(SERVER).cpp $(CPPFLAGS)

Auxiliary.o : Auxiliary.cpp Auxiliary.h
	$(CPP) Auxiliary.cpp $(CPPFLAGS)

SysLog.o : SysLog.cpp SysLog.h
	$(CPP) SysLog.cpp $(CPPFLAGS)

Secure.o : Secure.cpp Secure.h
	$(CPP) Secure.cpp $(CPPFLAGS)


# #############################################
#
# Utilities
#
clean :
	-rm -rf *.o $(SERVER) $(EXECUTABLE)

backup : clean tar
	rsync -arv ~/$(SERVER)/* babak@geeksdominion.com:/home/share/tcpip/devserver/$(SERVER)/
	
tar :
	tar cvf ~/$(SERVER)/Backups/$(EXECUTABLE).tar Makefile *.cpp *.h && echo && ls -l ~/$(SERVER)/Backups/$(EXECUTABLE).tar && echo

