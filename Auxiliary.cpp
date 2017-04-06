//
//  Auxilary.cpp
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

#include "Auxiliary.h"

//////////////////////////////////////////////////////////////////////////////
// Utilities

string ASCII_to_POSIX(string & href)
{
	stringReplace(href, " ", "\\ ");
	stringReplace(href, "(", "\\(");
	stringReplace(href, ")", "\\)");
	stringReplace(href, "^", "\\^");
	stringReplace(href, "&", "\\&");
	stringReplace(href, "$", "\\$");
	stringReplace(href, "#", "\\#");
	stringReplace(href, "!", "\\!");
	stringReplace(href, ";", "\\;");
	stringReplace(href, "@", "\\@");
	stringReplace(href, "'", "\\'");
	stringReplace(href, "\"", "\\\"");

	return href;
}

int exec(ostringstream &oss, int loglvl ) {
    
    vector <string> output;
    
    int stat = exec( oss.str(), &output, NULL, loglvl);
    oss.str("");
    if ( stat == 0 && output.size() > 0 )
        for( int i = 0; i < output.size(); i++ )
			oss << output[i]  <<endl;
    
    return stat;
    
}

string 	s_exec(  string str ) {
 
	string cmd = str;
    if( exec( cmd, LOG_ERR) == 0 )
        return cmd;
    else
        return "";
}

int exec( string &cmd,  int loglvl ) {
    
    vector <string> output;
    
    int stat = exec( cmd, &output, NULL,  loglvl );
    cmd = "";
    if ( stat == 0 && output.size() > 0 )
        cmd = output[0];
    
    return stat;
}


//int exec( vector <string> &output, char *envp[], int loglvl ) { 
int exec( vector <string> &output, int loglvl ) { 
    
    ThreadLog tlog("exec(vector)", loglvl);
    
    if ( output.size() > 0 && output[0].length() > 1 ) {
        string stemp = output[0];
        output.clear();
        return exec( stemp, &output, NULL, loglvl);
    } else {
        tlog.ERR( "No command find to execute!?");
        return -1;
    }
}

int exec( string cmd, vector <string> *myvec, char *envp[], int loglvl )
{
	ThreadLog tlog("exec(string, vector)", loglvl);
    
    cmd = trim( cmd );

    if ( cmd.length() < 1 ) {
        tlog.ERR( "no command to execute!?" );
        return -1;
    }
    
    cmd.append( " 2>&1\n" );
    tlog.INFO( cmd );

	if ( envp != NULL )		
		while ( *envp != NULL ) {
		
			tlog.DEBUG( *envp++ );
		}
	
	pid_t my_pid, parent_pid, child_pid;
	int status = 0;
	int pipefd[2];
    
	#define NUM_PIPES          2

	#define PARENT_WRITE_PIPE  0
	#define PARENT_READ_PIPE   1

	#define READ_FD  0
	#define WRITE_FD 1

	#define PARENT_READ_FD  ( pipes[PARENT_READ_PIPE][READ_FD]   )
	#define PARENT_WRITE_FD ( pipes[PARENT_WRITE_PIPE][WRITE_FD] )

	#define CHILD_READ_FD   ( pipes[PARENT_WRITE_PIPE][READ_FD]  )
	#define CHILD_WRITE_FD  ( pipes[PARENT_READ_PIPE][WRITE_FD]  )

    int pipes[NUM_PIPES][2];
    int outfd[2];
    int infd[2];
    
    // read and write pipes for parent to child
    if ( pipe(pipes[PARENT_READ_PIPE]) != 0 ) {
        tlog.ERR("ERROR: pipe() PARENT_READ_PIPE filaed!?");
        perror("pipe");
        return -1;
    }

    if ( pipe(pipes[PARENT_WRITE_PIPE]) != 0 ) {
        tlog.ERR("ERROR: pipe() PARENT_WRITE_PIPE filaed!?");
        perror("pipe");
        return -1;
    }
    
	// read and write pipes for parent to child
    if ( myvec != NULL ) {
		
		if ( pipe(pipefd) != 0 ) {
			
			tlog.ERR("ERROR: pipe filaed!?");
			perror("pipe");
			return -1;
		}
	}
	
	//get and print my pid and my parent's pid.
    my_pid = getpid(); // current executed ID    
    parent_pid = getppid(); // Bash shell starting process ID
   
    tlog.DEBUG( " parent id: " + to_string( parent_pid ));
	
	tlog.DEBUG( "process id: " + to_string( my_pid ));

	// print error message if  fork() fails 
   if((child_pid = fork()) < 0 )
   {
		tlog.ERR("ERROR: fork failure");
		return -1;
	}

	tlog.DEBUG( "    fork(): " + to_string(child_pid));
	
   if( ! child_pid ) { // chile_pid !=0 -> true;
        
        tlog.setPrefix("child");

	    int i, lfp;
		
		pid_t SID = setsid();
		tlog.DEBUG( "... setsid(): " + to_string( SID ) ); // obtain a new process group

		i = getdtablesize();
		tlog.DEBUG( "... getdtablesize(): " + to_string( i ) );
		
        if ( dup2(CHILD_READ_FD, STDIN_FILENO) < 0 )
            tlog.ERR("... Child Error redirecting STDIN" ); //0);  // send stdin to the pipe
        
        if ( dup2(CHILD_WRITE_FD, STDOUT_FILENO) < 0 )
            tlog.ERR("... Child Error redirecting STDOUT" ); //1);  // send stdout to the pipe
		
        if ( dup2(CHILD_WRITE_FD, STDERR_FILENO) < 0 )
            tlog.ERR("... Child Error redirecting STDOUT" ); //2);  // send stderr to the pipe

        // Close fds not required by child. Also, we don't
        // want the exec'ed program to know these existed
        close(CHILD_READ_FD);
        close(CHILD_WRITE_FD);
        close(PARENT_READ_FD);
        close(PARENT_WRITE_FD);            

        umask( 027 ); // set newly created file permissions
        SysLog::INFO( "... set umask: 027" );

		// A server should run in a known directory.
		SysLog::INFO( "... set Running Directory: ." ); // << RUNNING_DIR
		chdir( "." ); // change running directory

        pid_t my_pid, parent_pid, child_pid;
		my_pid = getpid(); // this is child ID    
		parent_pid = getppid(); // no it become the parent/main executed process ID

        SysLog::DEBUG( " parent id: " + to_string( parent_pid ));
		SysLog::DEBUG( " forked id: " + to_string( my_pid ));
		
		signal( SIGCHLD, SIG_IGN ); // ignore child terminate signal // TODO getting: "Can't ignore signal CHLD, forcing to default." on browser
		signal( SIGTSTP, SIG_IGN ); // ignore tty signals 
		signal( SIGTTOU, SIG_IGN );
		signal( SIGTTIN, SIG_IGN );
			
        char *argv[]={ (char *) "/bin/sh", 0};
                    
        // running the command in bash so it expands the wildcard *
        if ( execv( argv[0], argv ) <= 0 ) {
								
			perror("exec");
			tlog.ERR( "ERROR: execle(), ", errno );
            return -1;
		}
		
		_exit(EXIT_FAILURE);
		
		// THE CODE WOULD NEVER GET HERE!!!
		tlog.ERR("execvp() failure, the code should never reach to this point!", errno);
		cerr << "ERROR: " << strerror(errno) << endl;

    } else {
        
        tlog.setPrefix("parent");

			string recvBuffer = "";
			ostringstream respond;

			// close fds not required by parent 
            close(CHILD_READ_FD);
            close(CHILD_WRITE_FD);
			
            unsigned int bufsize = cmd.length();
 			char buffer[bufsize + 1]; // +1 to add termin. char.
            string line = "";
            
            strcpy( buffer, cmd.c_str());
                                
            write(PARENT_WRITE_FD, buffer, cmd.length());
            write(PARENT_WRITE_FD, "exit\n", 5);
            
            memset(buffer, 0x0, bufsize);
            
            int count;

            int cnt;
			// we could just to user the *myvec->xxx rather then output.xxx
            vector <string> & output = *myvec;

            while ( (cnt = read( PARENT_READ_FD, buffer, bufsize)) != 0 )
			{
                if ( myvec != NULL ) {
                    buffer[cnt] = '\0';
                      
                    stringstream ss;
                    ss << buffer;

                    string stemp;
                    while( getline(ss, stemp, '\n')) {
                        
                        if( stemp.find( "/bin/sh:") == 0) goto exit;
                        
                        output.push_back( line + stemp ); //stoi(number));
                        line = "";
                    }
                     
                    if ( buffer[cnt-1] != '\n' ) {
                        
                        line = output.at(output.size() -1);
                        output.pop_back();
                    }
                }
                memset(buffer, 0x0, bufsize);
                
            }
            
        wait(NULL);       // no matter what the parent waits for the child to finish
    }
            
    return 0;
exit:

    return -1;
}


bool isPrintable(string str)
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isprint( str[i] ) ) return false;
		//else cerr << "str: " << str[i] << " is OK" <<endl; 

	return true;
}

bool isAlphaNumDash(string str)
{
	return find_if(str.begin(), str.end(), 
				[](char c) -> bool { return !(isalnum(c) || (c == '-') || ( c == '_')); }) == str.end();
}

bool isNumeric(string str)
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isdigit( str[i] ) ) return false;

	return true;
}

bool isAlpha( string str )
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isalpha( str[i] ) ) return false;

	return true;
}

bool isAlphaNum( string str )
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isalnum( str[i] ) ) return false;

	return true;
}

bool isAlphaNumDashWS(string str)
{
	return find_if(str.begin(), str.end(), 
				[](char c) -> bool { return !(isalnum(c) || (c == '-') || ( c == '_') || c == ' '); }) == str.end();
}

bool isAlphaWS( string str )
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isalpha( str[i] ) && str[i] != ' ' ) return false;

	return true;
}

bool isAlphaNumWS( string str )
{
	for ( int i = 0; i < str.length() ; i++ )
		
		if ( ! isalnum( str[i] )  && str[i] != ' ' ) return false;

	return true;
}

bool isEmail( string str ) {
	
	size_t at, dot, len = str.length();

	if ( len < 5 ) return false;
    if ( ( at  = str.find_first_of( '@' )) == string::npos ) return false;
    if ( ( dot = str.find_last_of( '.' ))  == string::npos ) return false;

	if ( ! isAlphaNumDash( str.substr(   0, at )))		return false;
	if ( ! isAlphaNumDash( str.substr(  at + 1, dot - at -1 )))	return false;
	if ( ! isAlphaNumDash( str.substr( dot + 1 )))		return false;

	return true;
}

string trim(string str)
{
	size_t s = str.find_first_not_of(" \n\r\t");
	size_t e = str.find_last_not_of (" \n\r\t");

	if(( string::npos == s) || ( string::npos == e))
		return "";
	else
		return str.substr(s, e-s+1);
}

string toUpperCase( string &str ) {
	// http://stackoverflow.com/questions/7131858/stdtransform-and-toupper-no-matching-function
	transform( str.begin(), str.end(), str.begin(), (int (*)(int))std::toupper );
	return str;
}

string uuidgen()
{
	string mybuf;

	FILE * fp = popen("uuidgen", "r");

	int posix_handle = fileno(fp);
	__gnu_cxx::stdio_filebuf<char> filebuf(posix_handle, std::ios::in); // 1
	istream ins(&filebuf); // 2

	getline(ins, mybuf);
	pclose(fp);

	return trim(mybuf);
}

string 	formattedTime( time_t t ) {
	return formattedTime( t, false );
}

string 	formattedGMTTime( time_t t ) {
	return formattedTime( t, true );
}

string formattedTime(time_t timer, bool GMT) // true = GMT; false = US Local time;
{
	ostringstream output;
	struct tm ts;


	const char * weekdays[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char * mounths[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	                             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	if ( GMT ) *gmtime_r( &timer, &ts );
	else *localtime_r( &timer, &ts );

	// ie: Sun, 16 Feb 2014 19:59:56 GMT
	output << weekdays[ts.tm_wday] << ", " << ts.tm_mday << " " << mounths[ts.tm_mon] << " "
	       << ts.tm_year+1900 << " " << ts.tm_hour << ":" << ts.tm_min << ":" << ts.tm_sec << " " << ts.tm_zone;
    
    return output.str();
}

void stringReplace(string &href, string from, string to, bool all)
{
	size_t pos = 0;

	while((pos = href.find(from, pos)) != std::string::npos) {
		href.replace(pos, from.length(), to);
		pos += to.length();
		if ( !all ) break;
	}
}


//////////////////////////////////////////////////////////////////////////////
cmdOpt::cmdOpt(string cmdopts)
{
	//cmdopts pattern:
	// % the next switch to % is mandatory
	// : switch prior to : must take value after an space

	if (cmdopts != "" ) 
	{
		Flags temp;
		temp.flag = false;

		for (int i =0; i < cmdopts.size(); i++) 
		{
			temp.value = "";

			switch (cmdopts[i]) 
			{
			case '%':
				mandatory.push_back(cmdopts[i+1]);
				break;
			case ':':
				options[options.size()-1].value = "?";
				break;
			default:
				temp.attrib = cmdopts[i];
				options.push_back(temp);
			}
		}
	}
}

int cmdOpt::init(int argc, char *argv[])
{
	bool unknown;

	if (options.size() == 0 ) return 0;

	for (int i = 1; i < argc ; i++) {
		if (argv[i][0] != '-') {
			arguments.push_back(argv[i]);
			continue;
		}

		for (int j = 1; j < strlen(argv[i]); j++) {
			unknown = true;

			// process options one by one
			for ( int k = 0; k < mandatory.size(); k++) {
				if (mandatory[k] == argv[i][j]) {
					mandatory.erase(mandatory.begin()+k);
					k--;
				}
			}

			for ( int k = 0; k < options.size(); k++) {
				if (options[k].attrib != argv[i][j]) continue;
				if ( options[k].value != "") {
					// It can not be the last argument in command line
					if ( i >= argc-1 || j != strlen(argv[i])-1 || argv[i+1][0] == '-' ) {
						errors << "Missing argument for parameter: -" << argv[i][j];
						return -1;
					}
					i++;
					options[k].value = argv[i];
					//set pointer to the end of current field to stop iteriation
					j = strlen(argv[i]);
				}

				options[k].flag = true;
				unknown = false;
				break;
			}
			if (unknown) warnings << " -" << argv[i][j];
		}
	}

	if ( mandatory.size() != 0 ) {
		errors << "missing mandatory option(s):";
		for ( int k = 0; k < mandatory.size(); k++)
			errors << " -" << mandatory[k];
		return -1;
	}
}

string cmdOpt::getErrors()
{
	return errors.str();
}
string cmdOpt::getWarnings()
{
	return warnings.str();
}
bool cmdOpt::anyWarnings()
{
	if ( warnings.str().size() > 0 ) return true;
	else return false;
}

bool cmdOpt::isSet(char c)
{
	int index;
	return isSet(c, index);
}

bool cmdOpt::isSet(char c, int &index)
{
	for ( int i = 0; i < options.size(); i++)
		if ( options[i].attrib == c ) {
			index = i;
			return options[i].flag;
		}
	index = -1;
	return false;
}

string cmdOpt::getValue(char c)
{
	int index;
	if ( isSet(c, index)) {
		return options[index].value;
	} else return "";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
fileWrapper::fileWrapper( int logLvl) 
{
	loglevel = logLvl;
	tlog = new ThreadLog( "fileWrapper", logLvl );
	tlog->setID( "fw" );
	
	//fLock = new fileLock(loglevel);
	//tlog->EMERG("fw CONSTRUCTOREEEEEEEEEEEEE log level: " + to_string(loglevel));
}
	
fileWrapper::~fileWrapper() 
{
	//fLock->~fileLock();
    delete(tlog);
    //delete(fLock);
}

int fileWrapper::init( string FName )
{
	tlog->setPrefix( "init" );
	
	ETag = "";
    
	if ( FName.length() < 1 ) { tlog->ERR( "ERROR: FName len: 0" ); return -1; }
	
	fname = FName;
	
	tlog->DEBUG( "init fname: " + fname );

	fileExists = false;
    IS_DIR = false;
    
	if ( ! isValidFilename() ) 
	{
		tlog->DEBUG( "406: filename is not valid: " + fname );
		RC = 406;
		return RC;
	}

	if ( lstat( fname.c_str(), &fstat ) == -1 ) 
	{
		tlog->DEBUG( "404: file doesn't exists: " + fname );
		RC = 404;
		return RC;
	}

	if ( ! ( fstat.st_mode & S_IRUSR ) ) 
	{
		tlog->DEBUG( "403: file access permission is denied: " + fname );
		RC = 403;
		return RC;
	}

	if ( ! ( S_ISDIR( fstat.st_mode ) ) ) 
	{
		tlog->DEBUG( "200: regular file: " + fname );
		IS_DIR = false;

	} else {

		IS_DIR = true;

		if ( fname[fname.size()-1] == '/' )
		{
			tlog->DEBUG( "removing '/' from dir. name" );
			fname = fname.substr(0, fname.size()-1);
		}

		tlog->DEBUG( "200: regular directory: " + fname );
	}

	fileExists = true;
	RC = 200;

	return RC;
}

bool fileWrapper::isValidFilename()
{
//	static const std::string unreserved = "0123456789"
//										  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
//	                                      "abcdefghijklmnopqrstuvwxyz"
//	                                      "-_.~" ;
	static const string reserved = "\\:*?\"<>|&"; //  '\' ':' '*' '?' '"' '<' '>' '|'

	for ( int i = 0; i < reserved.length(); i++)
		if ( fname.find(reserved[i]) != string::npos ) return false;

	return true;
}

string fileWrapper::lastAccessed( bool GMT )
{
	if ( fileExists )
		return formattedTime( fstat.st_atime, GMT );
	else
		return "";
}

string fileWrapper::lastModified( bool GMT )
{
	if ( fileExists )
		return formattedTime( fstat.st_mtime, GMT );
	else
		return "";
}

string fileWrapper::getetag(bool CHK_DIR)
{
	tlog->setPrefix( "getetag" );

    if ( ETag != "" && isNumeric(ETag)) return ETag;
    
	if ( CHK_DIR && IS_DIR ) {
		return "";
	}

	if ( RC != 200 ) {
		tlog->ERR( "ERROR: getetag(): file dosn't exists." );
		return "";
	}

    ostringstream comm;
    
	string tempstr;
	tempstr = fname;
	
    comm << "cksum " << ASCII_to_POSIX( tempstr );
    
	tlog->DEBUG( "   cmd: " + comm.str() );
	
	if ( exec( comm ) != 0 )
	{
		tlog->ERR("ERROR: getetag() command failed!");
		return "";
	}
	
    tlog->DEBUG( "result: " + comm.str() );
	
	tempstr = comm.str().substr(0, comm.str().find_first_of(" "));

    // remove white spaces
	tempstr.erase( remove_if( tempstr.begin(), tempstr.end(), ::isspace ), tempstr.end() );
	tlog->DEBUG( "etag: " + tempstr );
    ETag = tempstr;

	return ETag;
}

int fileWrapper::mkDir() {
    
	tlog->setPrefix( "mkDir" );
	
    if ( RC == 200 ) {
        tlog->INFO( "201: directory was already exists" );
        return 201;
    }
    
    string cmd = "mkdir -p \"";
    cmd.append( fname + "\"" );
    
    if ( exec( cmd, loglevel ) == 0 )
        return 201;
    else
        return 500;
}

int fileWrapper::lsDir(vector <string> *output)
{
	tlog->setPrefix( "lsDir" );
    
	int cnt = -1;
    
    if ( RC !=  200 || ! IS_DIR ) return 0;
     
    DIR *pDir = opendir ( fname.c_str() );

    if (pDir == NULL) {
        tlog->ERR("500: ERROR lsDir() Cannot open directory");
        return cnt;
    }
    
    cnt = 0;
    struct dirent *pDirent;
        
    while (( pDirent = readdir(pDir) ) != NULL ) {
                
        if ( string(pDirent->d_name) == "." || string(pDirent->d_name) == ".." ) continue;
            
        if ( output != NULL) output->push_back( string(pDirent->d_name) );
        cnt ++;
    }
                        
    closedir (pDir);
    return cnt;
}

int fileWrapper::rmDir( bool force_all ) {

    tlog->setPrefix( "rmDir" );
    
	if ( ! IS_DIR ) { 
        tlog->DEBUG( "417: rmDir() Expectation failed, resource is a file!?" ); 
        return 417;  // 423 locked, 405 not allowed, 403 not permitted
    }
    
    vector <string> list;
            
    if ( lsDir( &list ) != 0 ) {

        if ( force_all ) {
            // recursively remove all sub-objects
            fileWrapper temp( loglevel );

            tlog->DEBUG( "force_all flag is set, objects: " + to_string( list.size()) );

            for ( int i = 0; i < list.size(); i++ ) {
                
                temp.init( fname + "/" + list[i] );
                if ( temp.IS_DIR )
                    temp.rmDir( force_all );
                else
                    temp.rmFile();
            }
        } else {
            tlog->DEBUG( "424: Dependency error, directory is not empty" ); 
            return 424; 
        }
    } 
        
    if ( remove( fname.c_str() ) != 0 ) {
        tlog->DEBUG( "500: ERROR(" + to_string(errno) + ") remove(): " + string(strerror(errno)) ); 
        return 500; 
    } 
        
    tlog->DEBUG( "201: rmDir() successfull." ); 
    RC = 200;
    return 204;
}

int fileWrapper::mkFile( bool force ) {

    tlog->setPrefix( "mkFile" );
    
    if ( RC == 200 ) {
        if ( IS_DIR ) {
            tlog->DEBUG( "417: failed, target exists as directory!" );
            return 417;
        } else {
            if ( force )
                tlog->DEBUG( "to truncate existing file!" );
            else {
                tlog->DEBUG( "403: file already exists!" );
                return 403;
            }
        }
    } else {

        string orig = fname;
    
        fname = DirName( fname );
    
        if ( fname != "" ) {

            mkDir();
        }
        
        fname = orig;
    }
    
    ofstream File;
    
    File.open( fname.c_str(), ofstream::out | ofstream::trunc );
    File.close();
    
    if ( lstat( fname.c_str(), &fstat ) == -1 ) 
	{
		tlog->DEBUG( "500: an error occured!?" );
		RC = 500;
		return RC;
	}

    tlog->DEBUG( "201: File created successfully" );
    RC = 200;
	return 201;
}

int fileWrapper::write( ostringstream *output, bool append )
{
	tlog->setPrefix( "write" );
    
	if ( RC != 200 ) {
        tlog->DEBUG( to_string(RC) + ": write() file doesn't exists or permission is not right!" );
        return RC;
    }

    if ( IS_DIR ) {
        tlog->DEBUG( "417: mkFile() expectation failed, resource is directory!" );
        return 417;
    }

    ofstream File;
    
	if ( append ) {
		tlog->DEBUG( "write() appending content");
		File.open( fname.c_str(), ofstream::app );
	} else {
		tlog->DEBUG( "write() truncate the file and re-write");
		File.open( fname.c_str(), ofstream::out | ofstream::trunc );
	}

    if ( output != NULL )
        File << output->str();
	else
        tlog->DEBUG( "write() the content is NULL" );
        
    File.close();

    if ( lstat( fname.c_str(), &fstat ) == -1 ) 
	{
		tlog->DEBUG( "500: write() An error occured: " + fname );
		RC = 500;
		return RC;
	}

    tlog->DEBUG( "201: write() updated successfully" );
	return 201;
}

int fileWrapper::rmFile() {
    
	tlog->setPrefix( "rmFile" );
    
    if ( IS_DIR ) { 
        tlog->DEBUG( "417: rmFile() Expectation failed, resource is a directory!?" ); 
        return 417; 
    }
    
    if ( remove( fname.c_str() ) != 0 ) {
        tlog->DEBUG( "500: ERROR(" + to_string(errno) + ") remove(): " + string(strerror(errno)) ); 
        return 500; 
    }

    tlog->DEBUG( "201: rmFile() successfull." ); 
    return 204;
}

int fileWrapper::read(stringstream &output)
{
	tlog->setPrefix( "read" );
    
	if ( RC != 200 ) {
        tlog->DEBUG( to_string(RC) + ": read() file doesn't exists or permission is not right!" );
        return RC;
    }

    if ( IS_DIR ) {
        tlog->DEBUG( "417: read() expectation failed, resource is directory!" );
        return 417;
    }

    int cnt = 0;
    string line;
    ifstream infile;
    infile.open( fname.c_str() );
    
    while ( ! infile.eof() ) {

        getline(infile, line);
		if ( ! infile.eof() )
			{ output << line << endl; cnt ++; }
		else
			break;
			
		tlog->DEBUG( to_string( cnt) + ") line: " + line );
    }
    
    infile.close();
    tlog->DEBUG( "200: read() lines: " + to_string(cnt) );
    
    return 200;
}

string fileWrapper::DirName(string fname)
{
    if (fname[fname.length()-1] == '/')
        return fname.substr(0, fname.length()-1);
        
	char *temp = new char[fname.length() + 1];
	strcpy(temp, fname.c_str());
    fname = dirname(temp);
    delete [] temp;
    return fname;
}


string fileWrapper::BaseName(string fname)
{
    if (fname[fname.length()-1] == '/')
        return "";

	char *temp = new char[fname.length() + 1];
	strcpy(temp, fname.c_str());
    fname = basename(temp);
	delete [] temp;
    return fname;
}

 /* 
bool fileWrapper::ls(  vector <string> &list, string wildcard, int discardFileLengths)
{
	tlog->appendPrefix("ls()");
	if ( ! fileExists ) return false;

	ASCII_to_POSIX( fname );
	//discardFileLengths = 4;
	
	tlog->INFO( "wild: " + wildcard + ", filter size: " + to_string( discardFileLengths ));
	
	if ( wildcard != "" && IS_DIR && wildcard[0] != '/')
	{
		tlog->INFO( "wildcard update, insert '/' on directory resource");
		wildcard.insert(0, "/");
	}
	
	string cmd = "ls -d " + fname + wildcard + " | grep -v -E '/[[:alpha:]]{" + to_string(discardFileLengths) + "}$'";
	
	tlog->INFO( "cmd: " + cmd );
	exec( cmd, &list );
		
	
	//if ( IS_DIR )
	//	// get the directory name greater than 4 character length.
	//	exec( "ls -d " + fname + "/* | grep -v -E '/[[:alpha:]]{3}$'", list );
	//else
	//	exec( "ls -d " + fname + "   | grep -v -E '/[[:alpha:]]{3}$'", list );


	if ( list.size() > 0 )
		return true;
	else
		return false;
}

string fileWrapper::findValue( string attrib )
{
	string line;
	ifstream infile;
	infile.open( fname.c_str() );

	//while ( getline( infile, line ) > 0 ) 
        while ( getline( infile, line ))     
	{
		line = trim( line );
		// found the attrib
		if ( line == attrib ) 
		{
			getline( infile, line );
			line = trim( line );
			
			if ( line == "\r" ) line = "";
			
			infile.close();
			return line;
		}
	}

	infile.close();

	return "";
}

bool fileWrapper::getValue( string &attrib )
{
	bool status = false;
	string line;
	ifstream infile;
	
	infile.open( fname.c_str() );

	//        while ( getline( infile, line ) > 0 ) {
	while ( getline( infile, line )) {
		
		// TODO make sure whitespaces does nto cause problem
		line = trim( line );
		
		// found the attrib
		if ( line == attrib ) {
			
			getline( infile, line );
			line = trim( line );
			
			if ( line != "" && line != "\r" ) {
				attrib = line;
				status = true;
			} else {
				attrib = "";
				status = false;
			}
			break;
		}
	}

	infile.close();

	return status;
}

bool fileWrapper::getValue( string attrib, vector <string> &values )
{
	string line;
	ifstream infile;
	infile.open(fname.c_str());

        //while ( getline(infile, line) > 0 ) {
	while ( getline(infile, line)) {

		// found the values
		if ( line == attrib) {
		        //while ( getline(infile, line) > 0 ) {
			while ( getline(infile, line)) {
				
				if ( line != "" && line != "\r" )
					values.push_back(line);
				else
					break;
			}
			
			break;
		}
	}

	infile.close();

	if ( values.size() > 0 ) return true;
	else return false;
}

bool fileWrapper::setValue( string attrib, string value, bool APPEND )
{
	bool status = false;
	string line, tmpName;

	ifstream infile;
	ofstream outfile;

	tmpName = fname + ".temp";
	infile.open(fname.c_str());
	outfile.open(tmpName.c_str(), ofstream::binary);

	//while (!infile.eof()) {
	while ( getline(infile, line))
	{
		//if ( getline(infile, line) == 0 ) break;
		
		outfile << line << endl;

		// found the attrib
		if ( !status && line == attrib) 
		{
			//do {
			//	if ( APPEND && line != value ) 
			//	outfile << line << endl; 
			//
			//	if ( line != "" && line != "\r") break;
			//		
			//} while ( getline(infile, line) > 0  );
			
			
                        //while ( getline(infile, line) > 0  )
			while ( getline(infile, line)) 
			{
				if ( line == "" || line == "\r") break;
				if ( APPEND && line != value ) 
					outfile << line << endl; 
			}
			
			outfile << value <<endl;
			
			//getline(infile, line);
//			if ( APPEND && line != "" ) outfile << line << endl;
//			outfile << value << endl;
			
			outfile << endl;
			status = true;
		}
	}

	if ( !status ) {
		outfile << endl << attrib << endl << value << endl << endl;
	}

	infile.close();
	outfile.close();

	tmpName.insert( 0, "mv \"" );
	tmpName.append( "\" \"" + fname + "\"" );
	system( tmpName.c_str());

	return status;
}

bool fileWrapper::ckValue( string attrib )
{
	return ckValue( attrib, "");
}

bool fileWrapper::ckValue( string attrib, string value )
{
	bool status = false;
	string line;
	ifstream infile;

	infile.open(fname.c_str());

	//while ( getline(infile, line) > 0 ) {
        while ( getline(infile, line)) {

		if ( line != attrib ) continue;
		
		if ( value == "" ) 
			status = true;
		else {
                        //while ( getline(infile, line) > 0 ) {
			while ( getline(infile, line)) {
				if ( line == "" || line[0] == '\r' || line[0] == '\n' ) break;
			
				if ( line == value ) {
					status = true;
					break;
				}
			}
		}

		break;
	}

	infile.close();
	return status;
}

 
bool fileWrapper::insValue( string attrib, string value )
{
	bool status = false, isAttrib = false;
	string line, tmpName;

	ifstream infile;
	ofstream outfile;

	// attrib=value is already exists
	//if ( ckValue(attrib, value) ) return true;
	
	tmpName = fname + ".temp";
	infile.open(fname.c_str());
	outfile.open(tmpName.c_str(), ofstream::binary);

        //while ( getline( infile, line ) > 0) {
	while ( getline( infile, line )) {

		outfile << line << endl;

		// found the attrib
		if ( !status && line == attrib ) {

                        //while (getline(infile, line) > 0 ) {
			while (getline(infile, line)) {
		
				if ( line == value ) break; // value is already there

				// end of paragraph, value not find, then add it.
				if ( line == "" || line == "\r") { outfile << value << endl; break; }
				outfile << line << endl;
			}
			outfile << line << endl;
			status = true;
		}
	}
	
	if ( ! status ) 
		outfile << attrib << endl << value << endl << endl;
	
	infile.close();
	outfile.close();

	tmpName.insert( 0, "mv \"" );
	tmpName.append( "\" \"" + fname + "\"");
	system( tmpName.c_str());

	return true;
}

bool fileWrapper::rmValue( string attrib, string value )
{
	bool status = false;
	string line, tmpName;

	ifstream infile;
	ofstream outfile;

	tmpName = fname + ".temp";
	infile.open(fname.c_str());
	outfile.open(tmpName.c_str(), ofstream::binary);

        //while (getline(infile, line) > 0) {
	while (getline(infile, line)) {

		outfile << line << endl;

		// found the attrib
		if ( !status && line == attrib ) {
                        //while (getline(infile, line) > 0 ) {
			while (getline(infile, line)) {
				
				if ( line == value ) {
					status = true;    // find the value, ignore it
					break;
				} else {
					outfile << line << endl;
				}

				if ( line == "" || line == "\r") break;
			}
		}
	}

	infile.close();
	outfile.close();

	tmpName.insert( 0, "mv " );
	tmpName.append( " " + fname );
	system( tmpName.c_str());

	return status;
}

*/

