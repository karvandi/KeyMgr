//
//  KeyMgr.h
//  KeyMgr
//
//  Keypair/Certificate manager main file, part of "an example programon using the Openssl library"
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

#ifndef  __Server_H_INCLUDED__   // if header hasn't been defined yet...
#define __Server_H_INCLUDED__   //   #define this so the compiler knows it has been included

#include "Auxiliary.h"
#include "Secure.h"

#include <unistd.h>
#include <term.h>

using namespace std;

// Global Pointer, structs, etc...
const char*	Version		= VERSION;
int			log_level	= LOG_INFO;
char		SSL_dir[64]	= { "./ssl/" };

void displayHelp( char * );

void ClearScreen();
void goodbye();

int initCSR( int, string&, OSSLCert& );
int initRootCACSR( string&, OSSLCA& );

int CSRQuery( string, OSSLCert& );
int mkKeypair( int, OSSLCert& );

void genKeypair( OSSLCert& );
void mainMenu();
void verifyMenu();
void CertMenu();
void CAMenu();

string selectKeypair		( string );
string selectCertificate	( string );
string selectCACertificate	( string );
string selectCSR			( string );
string selectFile			( string, string, string dirname = "" );

#endif
