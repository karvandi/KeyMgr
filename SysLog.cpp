//
//  SysLog.cpp
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

#include "SysLog.h"


SysLog::SysLog (int logLevel) 
{
	setlogmask ( LOG_UPTO ( logLevel ));
}

SysLog::~SysLog()
{
	closelog ();
}

void SysLog::setSysLogLevel( int logLevel )
{
	setlogmask ( LOG_UPTO ( logLevel ) );
}

void SysLog::EMERG( const string msg )
{
	syslog ( LOG_EMERG, "%s", string(msg).c_str() );
}

void SysLog::ALERT( const string msg )
{
	syslog ( LOG_ALERT, "%s", string(msg).c_str() );
}

void SysLog::ERR( const string msg )
{
	syslog ( LOG_ERR, "%s", msg.c_str() );
}

void SysLog::WARNING( const string msg )
{
	syslog ( LOG_WARNING, "%s", msg.c_str() );
}

void SysLog::INFO( const string msg )
{
	syslog ( LOG_INFO, "%s", msg.c_str() );
}

void SysLog::DEBUG( const string msg )
{
	syslog ( LOG_DEBUG, "%s", msg.c_str() );
}

//-- ostringstream ---------------------
void SysLog::EMERG ( ostringstream& msg )
{
	syslog ( LOG_EMERG, "%s", msg.str().c_str() );
	msg.str("");
}

void SysLog::ALERT ( ostringstream& msg )
{
	syslog ( LOG_ALERT, "%s", msg.str().c_str() );
	msg.str("");
}

void SysLog::ERR (ostringstream& msg)
{
	syslog (LOG_ERR, "%s", msg.str().c_str());
	msg.str("");
}

void SysLog::INFO (ostringstream& msg)
{	
	syslog (LOG_INFO, "%s", msg.str().c_str());
	msg.str("");
}

void SysLog::DEBUG (ostringstream& msg)
{	
	syslog (LOG_DEBUG, "%s", msg.str().c_str());
	msg.str("");
}

//######################################################################################
ThreadLog::ThreadLog ( int conn_id, const string main_id, int loglevel ) {
	
    //cout << "MAINCONSTRUCTOR" << endl;
    //procID = getpid();
    mainID = main_id;
    
    logLevel = loglevel;
    
    setPrefix( conn_id );
}

// ======== PREFIXE
void ThreadLog::setPrefix( int conn_id, string method_id )
{
	//procID = getpid();
	
    PREFIX.str("");

    PREFIX << "(" << getpid() << ")";
    //PREFIX << "(" << procID << ")";
    
    if ( mainID != "" )
        PREFIX << " " << mainID;
	
	if ( method_id.length() > 0 ) {
        
        if ( mainID != "" ) PREFIX << ".";
        else PREFIX << " ";
        
        PREFIX << method_id;
	}
    
    if( mainID != "" || method_id != "" || conn_id > -1 ) {
        
        if ( conn_id > -1 )
            PREFIX << "(" << conn_id << ")";
        else
            PREFIX << "()";
    }
    
    PREFIX << ": ";
}

//======= LOG METHODS
void ThreadLog::setLogLevel(int loglevel)
{
	if (loglevel < 0 || loglevel > 7 ) {
        SysLog::ALERT( "loglevel " + to_string(loglevel) + " out of range, set LOG_ERR(3)");
        logLevel = LOG_ERR;
    } else 
        logLevel = loglevel;
}

int ThreadLog::getLogLevel() {
    
    if ( logLevel > 0 ) {
        switch ( logLevel ) {
            case LOG_EMERG : // 0
                SysLog::EMERG("log level: LOG_EMERG");
                break;
                
            case LOG_ALERT :    // 1
                SysLog::DEBUG("log level: LOG_ALERT");
                break;
                
            case LOG_CRIT :    // 2
                SysLog::DEBUG("log level: LOG_CRTI");
                break;
                
            case LOG_ERR :     // 3
                SysLog::DEBUG("log level: LOG_ERR");
                break;
                
            case LOG_WARNING : // 4
                SysLog::DEBUG("log level: LOG_WARNING");
                break;
                
            case LOG_NOTICE :  // 5
                SysLog::DEBUG("log level: LOG_NOTICE");
                break;
                
            case LOG_INFO :   // 6
                SysLog::DEBUG("log level: LOG_INFO");
                break;
                
            default :        // 7
                SysLog::DEBUG("log level: LOG_DEBUG");
        } 
    }
    
    return logLevel;
}

void ThreadLog::EMERG(const string msg) // level 0
{
	syslog (LOG_EMERG,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

void ThreadLog::ALERT(const string msg) // level 1
{
	if ( logLevel >= 1 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

void ThreadLog::ERR(const string msg) // level 3
{
	if ( logLevel >= 3 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

void ThreadLog::WARNING(const string msg) // level 4
{
	if ( logLevel >= 4 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

void ThreadLog::INFO(const string msg) //level 6
{
	if ( logLevel >= 6 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

void ThreadLog::DEBUG(const string msg) // level 7
{
	if ( logLevel >= 7 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.c_str());
}

//-- ostringstream ---------------------
void ThreadLog::EMERG (ostringstream& msg) // level 0
{
	syslog (LOG_EMERG,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}

void ThreadLog::ALERT (ostringstream& msg) // level 1
{
	if ( logLevel >= 1 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}

void ThreadLog::ERR (ostringstream& msg) // level 3
{
	if ( logLevel >= 3 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}

void ThreadLog::WARNING (ostringstream& msg) // level 4
{
	if ( logLevel >= 4 ) 	
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}

void ThreadLog::INFO (ostringstream& msg) // level 6
{	
	if ( logLevel >= 6 ) 
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}

void ThreadLog::DEBUG (ostringstream& msg) // level 7
{	
	if ( logLevel >= 7 )
		syslog (LOG_ALERT,"%s%s", PREFIX.str().c_str(), msg.str().c_str());
	msg.str("");
}
