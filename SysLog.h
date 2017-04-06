//
//  SysLog.h
//  KeyMgr
//
//  interface to system's syslog, part of "an example programon using the Openssl library"
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

#ifndef __SYSLOG_H_INCLUDED__   // check if header hasn't been included yet...
#define __SYSLOG_H_INCLUDED__   //   #define this so the compiler knows it has been included

/*	cerr << "Log Levels: " 
			<< LOG_EMERG << " "	// 0
			<< LOG_ALERT << " "	// 1
			<< LOG_CRIT << " "		// 2
			<< LOG_ERR << " "   	// 3
			<< LOG_WARNING << " "	// 4
			<< LOG_NOTICE << " " 	// 5
			<< LOG_INFO << " " 	// 6
			<< LOG_DEBUG << endl;	// 7
*/

#include <iostream>		// cout, NULL
#include <syslog.h>		// syslog()
#include <sstream>		// stringstream
#include <cstring>      // strerror & memset
#include <unistd.h>     // getpid()

using namespace std;

// TODO: - have line to check rsyslog's rate-limiting in /etc/rsyslog.conf

class SysLog {
public:
    SysLog (int logLevel = LOG_ERR );
	~SysLog ();
	
	static void setSysLogLevel(int logLevel = LOG_ERR );

	static void EMERG (const string);
	static void ALERT( const string msg );
	static void ERR (const string);
	static void WARNING (const string);
	static void INFO (const string);
	static void DEBUG (const string);

	static void EMERG (ostringstream &);
	static void ALERT (ostringstream &);
	static void ERR   (ostringstream &);
	static void INFO  (ostringstream &);
	static void DEBUG (ostringstream &);
	
private:
};


class ThreadLog  : public SysLog 
{
private:
	int logLevel;
	
	//int procID;
	string  mainID;
	
	ostringstream PREFIX;

public:
    
	ThreadLog ( int, string, int loglevel = LOG_ERR );
	
    ThreadLog () : ThreadLog( -1, "", LOG_ERR) {}
	ThreadLog ( int loglevel ) : ThreadLog( -1, "", loglevel) {}
	ThreadLog ( const string main_id, int loglevel = LOG_ERR ) : ThreadLog( -1, main_id, loglevel ) {}
	
    ~ThreadLog () {};

	void resetPrefix    () { setPrefix(); }
	void setPrefix      (int conn_id = -1, const string method_id = "");
	void setPrefix      (const string method_id ) { setPrefix( -1, method_id ); }
    void setID          ( const string MID ) { mainID = MID; setPrefix(); }
	
	void setLogLevel(int);
	int  getLogLevel();
    
	void EMERG   (const string);
	void ALERT   (const string);
	void ERR     (const string);
	void WARNING (const string);
	void INFO    (const string);
	void DEBUG   (const string);

	void EMERG   (ostringstream &);
	void ALERT   (ostringstream &);
	void ERR     (ostringstream &);
	void WARNING (ostringstream &);
	void INFO    (ostringstream &);
	void DEBUG   (ostringstream &);

    void EMERG   (const string str, int err) { 
        EMERG(str + "(" + to_string(err) +") "   + string(strerror(err))); }
	void ALERT   (const string str, int err) { 
        ALERT(str + "(" + to_string(err) +") "   + string(strerror(err))); }
	void ERR     (const string str, int err) { 
        ERR(str + "(" + to_string(err) +") "     + string(strerror(err))); }
	void WARNING (const string str, int err) { 
        WARNING(str + "(" + to_string(err) +") " + string(strerror(err))); }
	void INFO    (const string str, int err) { 
        INFO(str + "(" + to_string(err) +") "    + string(strerror(err))); }
	void DEBUG   (const string str, int err) { 
        DEBUG(str + "(" + to_string(err) +") "   + string(strerror(err))); }

    void EMERG   (int err) { 
        EMERG( "EMERG (" + to_string(err) +") "     + string(strerror(err))); }
	void ALERT   (int err) { 
        ALERT( "ALERT (" + to_string(err) +") "     + string(strerror(err))); }
	void ERR     (int err) { 
        ERR( "ERR (" + to_string(err) +") "         + string(strerror(err))); }
	void WARNING (int err) { 
        WARNING( "WARNING (" + to_string(err) +") " + string(strerror(err))); }
	void INFO    (int err) { 
        INFO( "INFO (" + to_string(err) +") "       + string(strerror(err))); }
	void DEBUG   (int err) { 
        DEBUG( " DEBUG (" + to_string(err) +") "    + string(strerror(err))); }
};

#endif

// Some messages may be lost due to the system limit with the following error in syslog:
//
//	rsyslogd-2177: imuxsock begins to drop messages from pid 4065 due to rate-limiting
//
/* The package rsyslog-5.8.6-1ubuntu8.6.deb expects /dev/xconsole to be installed, 
 * but 'apt-file search /dev/xconsole' found no packages that provide it.
 * Comment it out near the end of /etc/rsyslog.d/50-default.conf :

# daemon.*;mail.*;\
# news.err;\
# *.=debug;*.=info;\
# *.=notice;*.=warn |/dev/xconsole
*/
//------------------
/*
// Add the following to the the /etc/rsyslog.conf, during the development:
$IMUXSockRateLimitInterval 0

// also comment out the following line, pops error dusing start up (it is legacy comand no longer permitted)
#$KLogPermitNonKernelFacility on
 

 // rsyslog configuration lines
 ///////////// GGGGGGGGGGGGGGGGOOOOOOOOOOOOOOOOOOOODDDDDDDDDDDDDDDDDD ///////////////
 *
 * vi /etc/rsyslog.d/00-tcp_server.conf and add the following

# if you just want to discard certain entries:
if $programname == 'server' and $msg contains 'Access From:' then /var/log/tcp_server/tcp_access.log
if $programname == 'server' and $msg contains 'Access From:' then stop
if $programname == 'server' then /var/log/tcp_server/tcp_server.log
if $programname == 'server' then stop

if $programname == 'pumchal' and $msg contains 'Access From:' then /var/log/tcp_server/tcp_access.log
if $programname == 'pumchal' and $msg contains 'Access From:' then stop
if $programname == 'pumchal' then /var/log/tcp_server/tcp_server.log
if $programname == 'pumchal' then stop

#& ~
 - old one -
# # if you just want to discard certain entries:
# if $programname == 'programname' then ~
# if $programname == 'programname' and $msg contains 'a text string' and $syslogseverity <= '6' then /var/log/custom/bind.log
#if $programname == 'server' and $syslogseverity <= '6' then /var/log/tcp_server/tcp_server.log
#if $programname == 'server' then /var/log/tcp_server/tcp_server.log
if $programname == 'test3'  then /var/log/tcp_server/tcp_server.log
if $programname == 'test3'  then ~
if $programname == 'server' and $msg contains 'Access From:' then /var/log/tcp_server/tcp_access.log
if $programname == 'server' and $msg contains 'Access From:' then ~
if $programname == 'server' then /var/log/tcp_server/tcp_server.log
if $programname == 'server' then ~

#& ~

// -- in file /etc/logrotate.d/rsyslog append:

/var/log/tcp_server/tcp_server.log
/var/log/tcp_server/tcp_access.log
{
        rotate 7
        daily
        size 200M
        missingok
        notifempty
        postrotate
                reload rsyslog >/dev/null 2>&1 || true
        endscript
}

 
*/

/* *****************************************************************************************************
 * void openlog (const char *ident, int option, int facility)
 * 
 * ident is an arbitrary identification string which future syslog invocations will prefix to each message.
 * If ident is NULL, or if openlog is not called, the default identification string used in 
 *  Syslog messages will be the program name, taken from argv[0]. 
 * 
 * options is a bit string, with the bits as defined by the following single bit masks:
 * LOG_PERROR	: 	writes its message to the calling process' Standard Error stream in addition
 * LOG_CONS	:	if fails to submit a message, Syslog writes the message to system console instead
 * LOG_PID		:	inserts the calling process' Process ID (PID) into the message
 * LOG_NDELAY	:	openlog opens and connects the /dev/log socket. When off, a future syslog call must 
 *   				open and connect the socket.
 * LOG_ODELAY	:	This bit does nothing. It exists for backward compatibility. 
 * 
 * facility is the default facility code for this connection. A syslog on this connection that specifies default 
 * facility causes this facility to be associated with the message. See syslog for possible values. A value of 
 * zero means the default default, which is LOG_USER.
 * 
 * syslog ( LGO_MAKEPRI(facility, priority), <mesage>);
   ie: syslog (LOG_MAKEPRI(LOG_LOCAL1, LOG_ERROR), "Unable to make network connection to %s.  Error=%m", host);

LOG_EMERG	:	0) The message says the system is unusable.
LOG_ALERT	:   1) Action on the message must be taken immediately.
LOG_CRIT	:   2) The message states a critical condition.
LOG_ERR		:   3) The message describes an error.
LOG_WARNING	:	4) The message is a warning.
LOG_NOTICE	:	5) The message describes a normal but important event.
LOG_INFO	:   6) The message is purely informational.
LOG_DEBUG	:   7) The message is only for debugging purposes.  

LOG_PERROR	: 	writes its message to the calling process' Standard Error stream in addition
LOG_CONS	:	if fails to submit a message, Syslog writes the message to system console instead
LOG_PID		:	inserts the calling process' Process ID (PID) into the message
LOG_NDELAY	:	openlog opens and connects the /dev/log socket. When off, a future syslog call must 
  				open and connect the socket.
LOG_ODELAY	:	This bit does nothing. It exists for backward compatibility. 
*/
