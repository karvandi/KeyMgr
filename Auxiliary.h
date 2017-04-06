//
//  Auxilary.h
//  KeyMgr
//
//  part of "an example programon using the Openssl library"
//
//  Created by Babak Karvandi on 04/06/2017.
//  Copyright (C) Geeks Dominion LLC 2017. All rights reserved.
//
//  This software is provided 'as-is', without any express or implied
//  warranty.  In no event will the authors be held liable for any damages
//  arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,
//  including commercial applications, and to alter it and redistribute it
//  freely, subject to the following restrictions:
//
//  1. The origin of this software must not be misrepresented; you must not
//     claim that you wrote the original software. If you use this software
//     in a product, an acknowledgment in the product documentation would be
//     appreciated but is not required.
//
//  2. Altered source versions must be plainly marked as such, and must not be
//     misrepresented as being the original software.
//
//  3. This notice may not be removed or altered from any source distribution.
//

#ifndef  __COMMON_H_INCLUDED__   // if header hasn't been defined yet...
#define __COMMON_H_INCLUDED__    // #define this so the compiler knows it has been included

#include "SysLog.h"

#include <iostream>				// cout
#include <pthread.h>			// create_thread ; Library is passes to the linker as well
#include <vector>				// vector
#include <sstream>				// stringstream
#include <string>				// string
#include <cstring>				// <cstring> = <string.h> ; (in C) strlen()
#include <unistd.h>				// getpid()
#include <map>					// map key-value pair
#include <fstream>				// ofstream (file type)
#include <algorithm>			// find_if(), remove_if(), toupper

#include <fcntl.h>				// fcntl, C style file write (used in daemonize)
#include <libgen.h>				// dirname()
#include <dirent.h>				// opendir(), readdir()

//#include <experimental/filesystem> // filesystem handling

#include <ext/stdio_filebuf.h>	// GNU stdio_filebuf for istream on system call

#include <sys/wait.h>			// wait(), wait for child process to finish
#include <sys/stat.h>			// fstat, umask
#include <sys/poll.h>			// POLL, fds

#include <termios.h>			// struct termios; Keyboard poll TC

#include <tr1/memory>			// smart pointers
#include <memory>				// smart pointers

using namespace std;

//////////////////////////////////////////////////////////////////////////////
// Utilities

string	ASCII_to_POSIX	(string &);

int 	exec			(ostringstream &, int loglvl = LOG_ERR );
string 	s_exec			( string );
int 	exec			( string &, int loglvl = LOG_ERR );
int 	exec			( vector <string> &, int loglvl = LOG_ERR );
int 	exec			( string cmd, vector <string> *myvec = NULL, char *envp[] = NULL, int loglvl = LOG_ERR );	
// runs the /bin/sh for wildcard char safety

bool 	isPrintable		( string );
bool 	isNumeric		( string );
bool 	isAlpha			( string );

bool 	isAlphaWS		( string );
bool 	isEmail			( string );

string	trim			( string );
string	toUpperCase		( string & );

string	uuidgen			();

string 	formattedTime	( time_t t = time(0));
string 	formattedGMTTime( time_t t = time(0));
string 	formattedTime	( time_t, bool GMT );		// true = GMT; false = US Local time;

void 	stringReplace	(string &, string, string, bool all = true); // true = All occuranses, false = First occurance

//////////////////////////////////////////////////////////////////////////////
class cmdOpt
{
public:
	cmdOpt				(string);
	~cmdOpt				() {};
	int init			(int, char *[]);
	string getErrors	();
	string getWarnings	();
	bool anyWarnings	();
	bool isSet			(char);
	bool isSet			(char, int &);
	string getValue		(char);
	
private:
	struct Flags {
		char attrib;
		string value;
		bool flag;
	};
	
	vector <Flags> options;
	vector <char>  mandatory;
	vector <string> arguments;
	
	ostringstream errors;
	ostringstream warnings;
};

//////////////////////////////////////////////////////////////////////////////////////////////////////
class fileWrapper
{
public:
	fileWrapper(int logLvl = LOG_ERR);
	~fileWrapper();
    
    int RC;
	bool fileExists, IS_DIR;
    string ETag;
    
	int init(string);

	bool isDir() { return IS_DIR; }
	bool isValidFilename();
	string lastAccessed(bool);
	string lastModified(bool);
	string getetag( bool CHK_DIR = true );
    int size() { if ( RC == 200 ) return fstat.st_size; else return -1; }
	
    int mkDir();
    int lsDir( vector <string> *output = NULL );
    int rmDir( bool force_all = false );
    
    int mkFile( bool force = false );
    int rmFile();
    int write( ostringstream *output = NULL, bool append = false );
    int append( ostringstream *output ) { return write( output, true ); };
    int erase() { write(); tlog->INFO( "204: erase() successfull" ) ; return 204; };
    int read( stringstream & );
    
	static string	DirName			( string );
	static string	BaseName		( string );

	string fname;
	
protected:
	struct stat fstat;
	int loglevel;
	
private:

	ThreadLog *tlog;
};

#endif
