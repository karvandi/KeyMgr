//
//  KeyMgr.cpp
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

#include "KeyMgr.h"

void displayHelp( char *argv )
{
		cerr <<endl;
		cerr << "\t" << argv << " [-h] [-d] [-F] [-S] [-f <config file path/name]" <<endl<<endl;
		cerr << "\t\t-l : log detailed information (/var/log/syslog)." <<endl;
		cerr << "\t\t-h : displays this help screen." <<endl;
		cerr << "\t\t-f <database file> : full path to the certificates/database directory." <<endl;
		cerr << "\t\t         (default) ./ssl/" <<endl;
		cerr <<endl;
}

void ClearScreen()
{ // http://www.cplusplus.com/forum/articles/10515/#msg49080
  if (! cur_term )
    {
    int result;
    setupterm( NULL, STDOUT_FILENO, &result );
    if (result <= 0) return;
    }

  putp( tigetstr( "clear" ) );
  
  cout <<endl<<endl;
}

void goodbye() {

	ClearScreen();
	cout <<endl<<endl<<endl<< "\tThank you for using our program. Goodbye..." <<endl<<endl<<endl<<endl;
	exit( 0 );	
}

string selectKeypair		( string cmnt ) { return selectFile( cmnt, "key", "private/" ); }
string selectCertificate	( string cmnt ) { return selectFile( cmnt, "crt" ); }
string selectCSR			( string cmnt ) { return selectFile( cmnt, "csr" ); }
string selectCACertificate	( string cmnt ) { return selectFile( cmnt, "crt", "trusted/"); }

string selectFile( string cmnt, string type, string dirname ) {
				
	int rc, idx;
	string in;
	
	vector <string> files;
	
	files.push_back( "ls -b " + string( SSL_dir) + dirname + "*." + type );
	
	rc = exec( files );
	
	if ( files.size() < 1 || files[0].find( "No such file or directory" ) != string::npos ) { 
		cout <<endl<< "\tNo " << type << " file find in " << SSL_dir << dirname <<endl;
		cout <<endl<<endl<< "\tPress any key to continue..."; getline ( cin, in );
		return "";
	}
	
	for ( int i = 0; i < files.size(); i ++ )
			stringReplace( files[i], string( SSL_dir) + dirname, "" );
	
	files.insert( files.begin(), "" );
	
	do { 
		cout <<endl<< cmnt <<endl<<endl;
		
		cout << "\t0) Cancel & Return" <<endl<<endl;
		
		for ( int i = 1; i < files.size(); i ++ )
			cout << "\t" << i << ") " << files[i] <<endl;
		
		cout <<endl<<endl<< "\t> "; getline ( cin, in );
		idx = atoi( in.c_str() );
		
		if ( idx < 0 || idx > files.size() -1 ) {
			cout <<endl<< "\tERROR: Wrong option!? " << idx <<endl;
			sleep( 2 );
			continue;
		}
		
		break;
		
	} while( true );
	
	if ( idx == 0 ) { cout <<endl<< "\tCanceled." <<endl; }
	else cout <<endl<< "\t " << idx << ") selected file: " << files[ idx ] <<endl;

	return files[ idx ];
}

int initCSR( int type, string& CN, OSSLCert& ossl ) {
	
	int rc;
	string in;
	
	CN = "\t EnterCertificate Title (Common Name): ";
	ClearScreen();
	do {
		rc = -1;
		cout << CN; getline ( cin, in );
					
		if ( in.length() < 5 || in.length() > 64  || ! isPrintable( in ))  {
			cerr <<endl<< "\tERROR: only alphanumeric values with dashes and WS are accepted (max. len. 64)." <<endl<<endl; continue; }
		
		switch( type ) {
			case 0 : { rc = ossl.initServerCSR( in.c_str()); break; }
			case 1 : { rc = ossl.initClientCSR( in.c_str()); break; }
			case 2 : { rc = ossl.initCACSR( in.c_str());     break; }
		}
		
		if ( rc == -1 ) { 
			cerr <<endl<< "\tERROR: You need to load/generate a keypair first!?" <<endl; 
			cout <<endl<< "\tPress any key to continue..." <<endl; getline ( cin, in );
			ClearScreen();
			return -1; 
		}

		CN.append( in );
		
	} while ( rc != 1 );
	
	return rc;
}

int initRootCACSR( string& CN, OSSLCA& ossl ) {
	
	int rc;
	string in;
	
	CN = "\t EnterCertificate Title (Common Name): ";
	ClearScreen();
	do {
		rc = -1;
		cout << CN; getline ( cin, in );
					
		if ( in.length() < 5 || in.length() > 64  || ! isPrintable( in ))  { 
			cerr <<endl<< "\tERROR: only alphanumeric values with dashes and WS are accepted (max. len. 64)." <<endl<<endl; continue; }
		
		rc = ossl.initRootCACSR( in.c_str());
		
		if ( rc == -1 ) { 
			cerr <<endl<< "\tERROR: You need to generate a keypair first!?" <<endl; 
			cout <<endl<< "\tPress any key to continue..." <<endl; getline ( cin, in );
			ClearScreen();
			return -1; 
		}

		CN.append( in );
		
	} while ( rc != 1 );

	return rc;
}

int CSRQuery( string CN, OSSLCert& ossl ) {

	int rc;
	string in;
	ostringstream out;

	out << CN <<endl;

	ClearScreen();
	out << "\tTwo letter country code:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 2 ) { out <<endl; break; }
		if ( in.length() != 2 || ! isAlpha( in ) ) { 
			cerr <<endl<< "\tERROR: enter two non-numeric letter only." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_Country( toUpperCase( in).c_str() )) != 1 ) { cerr <<endl<< "\tERROR: setting the Country Code: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );
	
	ClearScreen();
	out << "\tState/Province:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 15 || ! isAlphaWS( in ) ) { 
			cerr <<endl<< "\tERROR: only alpha-numeric and white-space char. are accepted (len. 15)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_Province( toUpperCase( in).c_str() )) != 1 ) { cerr <<endl<< "\tERROR: CSR_Province: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );
	
	ClearScreen();
	out << "\tCity:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 15 || ! isAlphaWS( in ) ) { 
			cerr <<endl<< "\tERROR: Only alpha-numeric and white-space char. are accepted (len. 15)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_City( toUpperCase( in).c_str() )) != 1 ) { cerr <<endl<< "\tERROR: CSR_City: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );

	ClearScreen();
	out << "\tOrganization:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 25 || ! isPrintable( in ) ) { 
			cerr <<endl<< "\tERROR: Only alpha-numeric and white-space char. are accepted (len. 25)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_Organization( toUpperCase( in).c_str() )) != 1 ) { cerr <<endl<< "\tERROR: CSR_Organization: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );

	ClearScreen();
	out << "\tEmail Address:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 25 || ! isEmail( in ) ) { 
			cerr <<endl<< "\tERROR: Only alpha-numeric and white-space char. are accepted (len. 25)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_Email( toUpperCase( in).c_str() )) != 1 ) { cerr <<endl<< "\tERROR: CSR_Email: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );

	ClearScreen();
	out << "\tComment:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 128 || ! isPrintable( in ) ) { 
			cerr <<endl<< "\tERROR: Only alpha-numeric and white-space char. are accepted (len. 128)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_Comment( toUpperCase( in).c_str() )) == -1 ) { cerr <<endl<< "\tERROR: CSR_Comment: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );

	ClearScreen();
	out << "\tServer Name:  "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 25 || ! isAlphaWS( in ) ) { 
			cerr <<endl<< "\tERROR: Only alphabet and white-space char. are accepted (len. 25)." <<endl<<endl; continue; }
		if ( in.length() > 4 ) {
			if ( ( rc = ossl.CSR_SSLServer_Name( toUpperCase( in).c_str() )) == -1 ) { cerr <<endl<< "\tERROR: CSR_SSLServer_Name: " << in <<endl; goto exitCSRQuery; }
		}
		out << in <<endl;
	} while( rc != 1 );

	ClearScreen();
	out << "\tSubject Alternative Name (ie: \"DNS:domain.com, DNS:*.domain.com, email:me@email.org\" )" <<endl<< "\t> "; 
	do {
		rc = -1;
		cout << out.str(); getline ( cin, in );
		if ( trim( in ).length() < 1 ) { out <<endl; break; }
		if ( in.length() > 128 ) { 
			cerr <<endl<< "\tERROR: Only alpha-numeric and white-space char. are accepted (len. 128)." <<endl<<endl; continue; }
		if ( ( rc = ossl.CSR_SAN( toUpperCase( in).c_str() )) == -1 ) { cerr <<endl<< "\tERROR: CSR_SAN: " << in <<endl; goto exitCSRQuery; }
		out << in <<endl;
	} while( rc != 1 );

/*
				ossl.CSR_Custom_Ext( "1.2.3.4", "Alias", "Test Alias Extension", "Custom Comment" );
				// oid "1.3.6.1.4.1" is already defined as Enterprises
*/
	ClearScreen();
	cout <<endl<<endl<< out.str() <<endl<<endl<<endl<<"\tDo you want to proceed (y/n)? ";
	getline ( cin, in );
	if ( trim( in ) == "y" ) { 
		if ( ( rc = ossl.mkCSR()) == -1 ) { cerr <<endl<< "\tERROR: mkCSR: " << in <<endl; goto exitCSRQuery; }
		else cout <<endl<< "\tmkCSR: 1" <<endl<<endl;
	} else { 
		rc = 0; cout <<endl<<endl<< "\tCancelled!" <<endl<<endl; 
	}
	
exitCSRQuery:

	sleep(1);
	ClearScreen();
	cout <<endl;
	
	return rc;	
}

int mkKeypair( int type, OSSLCert& ossl ) {

	int rc;
	char tmp[64];

	if ( type == 0 ) {
		cout << "\tmake ECC secp521r1 Keypair: " << ( rc = ossl.mkECCKeypair()) <<endl<<endl;
		sprintf( tmp, "ECC_private-%d.key", (int) time(0));
	} else {
		cout << "\tmake RSA F4 Keypair: " << ( rc = ossl.mkRSAF4Keypair()) <<endl<<endl;
		sprintf( tmp, "RSA_private-%d.key", (int) time(0));
	}

	if ( rc == -1 ) { cout <<endl; return -1; }
	
	cout <<endl;

	if( log_level > LOG_ERR ) ossl.writeKeypair();

	string pwd, in;
	
	cout <<endl<< "\tEnter file name of private/public keypair [" << tmp << "]: ";
	getline ( cin, in );
	
	if ( trim( in ).length() == 0 ) in = string ( tmp );
	if ( in.substr( in.length() - 4 ) != ".key" ) in.append( ".key" );
				
	cout <<endl<< "\tOptionally enter desiered password: ";
	getline ( cin, pwd );
	
	cout <<endl<< "\tKey pair filename: " << SSL_dir << "private/" << in << " : ";

	if( trim( pwd ).length() > 1 ) rc = ossl.writeKeypair( in.c_str(), pwd.c_str());
	else rc = ossl.writeKeypair( in.c_str() );
	
	cout << rc <<endl;
	
	return rc;
}

void MainMenu() {
	
	while ( true ) {
		
		char role[64];
		
		ClearScreen();
		
		cout <<"\tSelect from following options: " <<endl<<endl;
		
		cout <<"\t\t1) Basic Certificate verification" <<endl;
		cout <<"\t\t2) Keypair/Certificate request menu" <<endl;
		cout <<"\t\t3) Certificate Authority Options" <<endl<<endl;
		
		cout <<endl<< "\t\tq) exit" <<endl<<endl<<endl<< "\t\t> ";
		
		cin >> role; cin.ignore( 256, '\n' );
		
		if ( strlen( role ) > 1 ) { ClearScreen(); cout <<endl<< "\tERROR: Wrong option: " << role <<endl; sleep(1); continue; }
		
		switch ( role[0] ) {
		
			case '1' : {
				ClearScreen();
				verifyMenu();
				break;
			}

			case '2' : {
				ClearScreen();
				CertMenu();
				break;
			}

			case '3' : {
				ClearScreen();
				CAMenu();
				break;
			}

			case 'q' : {
				goodbye();
				break;
			}

			default : {
					ClearScreen();
					cout <<endl <<"\tERROR: Wrong option!? Try again: " << role[0] <<endl<<endl;
			}
		}
	}
}

void verifyMenu() {
	
	OSSL ossl( log_level, SSL_dir );
	
	ClearScreen();
	
	char role[64];
	
	int rc;
	string in = SSL_dir + string( "trusted/");
	string tmp;
		
	cout <<endl<< "\tEnter the path to the trusted cert.s folder [" << in << "] : "; getline( cin, tmp ); 
	if ( trim( tmp ).length() > 1 ) in = tmp;
	
	if ( ( rc = ossl.initTrusties( NULL, in.c_str())) < 1 ) {
		cout <<endl<< "\tinit Trusties(" << rc << "):  failed!?"<<endl;
		sleep( 2 );
		return;
	}
	cout <<endl<< "\tinit Trusties: OK" <<endl;
	sleep( 1 );

	while ( true ) {

		ClearScreen();
		
		cout <<"\tBasic SSL Verification tasks: " <<endl<<endl;
			
		cout <<"\t\t1) Add another trusted CA cert to trusties stack" <<endl<<endl;
			
		cout <<"\t\t2) Verify Slef-signed certificate" <<endl<<endl;
		cout <<"\t\t3) Verify certificate by trusties" <<endl;
		cout <<"\t\t4) Verify by Keypair" <<endl<<endl;
		
		cout <<endl<< "\t\tr) return to previouse menu" <<endl;
		cout       << "\t\tq) exit" <<endl<<endl<<endl<< "\t\t> ";
			
		cin >> role; cin.ignore( 256, '\n' );
			
		if ( strlen( role ) > 1 ) { ClearScreen(); cout <<endl<< "\tERROR: Wrong option: " << role <<endl; sleep(1); continue; }

		
		ClearScreen();
		
		switch ( role[0] ) {
		
			case '1' : { // Add extra trusted certificate to the trusties stack
				string in;

				string cacert = selectCertificate( "\tSelect CA Trusted Certificate:" );
				if ( cacert == "" ) break;
				
				cout <<endl<< "\tadd trusty: " << ossl.addTrusty( cacert.c_str()) <<endl;
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '2' : { // Verify Slef-signed Certificate
				int tot_certs = -1;

				string cert = selectCertificate ( "\tSelect Certificate:" );
				if ( cert == "" ) break;
				
				cout <<endl<< "\tNum. of Certificates found: " << ( tot_certs = ossl.readCertificate( cert.c_str())) <<endl;
				if ( tot_certs < 0 ) {
					cout <<endl<< "\tERROR: Failed to load Certificate file!?" <<endl<<endl;
					sleep( 2 );
					break;
				} else if ( tot_certs < 1 ) { 
					cout <<endl<< "\tNo certificate loaded!? tot_certs: " << tot_certs <<endl<<endl; 
					sleep( 2 ); 
					break; 
				}
				
				cout <<endl<< "\t----------------------------------------------------" <<endl;
					
				int rc;
				
				for ( int i = 0; i < tot_certs; i++ ) {
					if ( ossl.isSelfsignedCert( i )) { 
						cout <<endl<< "\t" << i << ") Self-Signed Certificate: true" <<endl;
						cout << "\t   Verify self-signed Cert.:" << ( rc = ossl.verifySelfsignedCert( i )) <<endl;
						if ( rc == 1 ) cout << "\t   Trusted Certificate: OK" <<endl; 
						else cout << "\t   error (" << ossl.getVerifyERRNumber() << "): " << ossl.getVerifyERRString() <<endl;					
					} else
						cout <<endl<< "\t" << i << ") Non Self-Signed Certificate: Skipped" <<endl<<endl;
				}
				
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}
			
			case '3' : { // Verify Cert. by trusties
				int tot_certs = -1;

				string cert = selectCertificate ( "\tSelect Certificate:" );
				if ( cert == "" ) break;
				
				cout <<endl<< "\tread Certificate: " << ( tot_certs = ossl.readCertificate( cert.c_str())) <<endl;
				if ( tot_certs < 1 ) {
					cout <<endl<< "\tERROR: Failed to load Certificate file!?" <<endl<<endl;
					sleep( 2 );
					break;
				} else if ( tot_certs < 1 ) { 
					cout <<endl<< "\tNo certificate loaded!? tot_certs: " << tot_certs <<endl<<endl;
					sleep( 2 ); 
					break; 
				}
				
				cout <<endl<< "\t----------------------------------------------------" <<endl;
				
				
				int rc;
				for ( int i = 0; i < tot_certs; i++ ) {
					if ( ossl.isSelfsignedCert( i )) { 
						cout <<endl<< "\t" << i << ") Self-Signed Certificate: Skipped" <<endl;
						continue;
					}
					
					cout <<endl<< "\t" << i << ") Verify Cert. by trusties: " << ( rc = ossl.verifyCertByTrusties( i )) <<endl;
					if ( rc == 1 ) cout << "\t   Trusted Certificate: OK" <<endl; 
					else cout << "\t   error (" << ossl.getVerifyERRNumber() << "): " << ossl.getVerifyERRString() <<endl;
					
				}
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}
			
			case '4' : { // Verify Cert. by Keypair
				int rc, tot_certs = -1;

				string cakey = selectKeypair( "\tSelect Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl<<endl;
				if ( rc < 1 ) {
					cout <<endl<< "\tERROR: Failed to load Keypair file!?" <<endl<<endl;
					sleep( 2 );
					break;
				}

				string cert = selectCertificate ( "\tSelect Certificate to be verified:" );
				if ( cert == "" ) break;
				
				cout <<endl<< "\tread Certificate: " << ( tot_certs = ossl.readCertificate( cert.c_str())) <<endl;
				if ( tot_certs < 1 ) {
					cout <<endl<< "\tERROR: Failed to load Certificate file!?" <<endl<<endl;
					sleep( 2 );
					break;
				} else if ( tot_certs < 1 ) { 
					cout <<endl<< "\tNo certificate loaded!? tot_certs: " << tot_certs <<endl<<endl;
					sleep( 2 ); 
					break; 
				}
								

				cout <<endl<< "\t----------------------------------------------------" <<endl;

				for ( int i = 0; i < tot_certs; i++ ) {
					
					if ( ossl.isSelfsignedCert( i ))	cout <<endl<< "\t" << i << ") Self-Signed Certificate: true" <<endl;
					else 								cout <<endl<< "\t" << i << ") Self-Signed Certificate: false" <<endl;

					
					cout << "\t   Verify Cert. by Keypair: " << ( rc = ossl.verifyCertByKeypair( i )) <<endl;
					if ( rc == 1 ) 	cout << "\t   Certificate match the Keypair: OK" <<endl; 
					else 			cout << "\t   Certificate match the Keypair: FALSE" <<endl; 
					
				}

				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}
			

			case 'r' : {
				return;
				break;
			}

			case 'q' : {
				goodbye();
				break;
			}

			default : {
					cout <<endl <<"\tERROR: Wrong option!? Try again: " << role[0] <<endl<<endl;
			}
		}
	}
}

void CertMenu() {

	OSSLCert ossl( log_level, SSL_dir );

	while ( true ) {
		
		ClearScreen();
		
		char role[64];
		
		cout <<"\tKeypair/Certificate Management: " <<endl<<endl;
		
		cout <<"\t\t1) Generate Public/Private Keypair" <<endl<<endl;
		
		cout <<"\t\t2) Generate Server Certificate Sign Request (CSR)" <<endl;
		cout <<"\t\t3) Generate Client CSR" <<endl;
		cout <<"\t\t4) Generate CSR from existing Certificate" <<endl<<endl;

		cout <<endl<< "\t\tr) return to previouse menu" <<endl;
		cout             << "\t\tq) exit" <<endl<<endl<<endl<< "\t\t> ";
		
		cin >> role; cin.ignore( 256, '\n' );
		
		if ( strlen( role ) > 1 ) { ClearScreen(); cout <<endl<< "\tERROR: Wrong option: " << role <<endl; sleep(1); return; } //continue; }

		ClearScreen();
		int rc;
		
		switch ( role[0] ) {
		
			case '1' : { // Generate Public/Private Keypair
				genKeypair( ossl );
				break;
			}

			case '2' : { // Generate Server Certificate Sign Request (CSR)
				string in;

				string cakey = selectKeypair( "\tSelect Signing Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout <<endl<< "\t init Cert Sign Req.: " << ( rc =  initCSR( 0, in, ossl )) <<endl;
				cout <<endl<< "\tCSR signature-length: " << ( rc =  CSRQuery( in, ossl )) <<endl;
				if ( rc < 1 ) { cout <<endl; break; }

				cout <<endl;
				
				if ( log_level > LOG_ERR) ossl.writeCSR();
				
				char tmp[64];
				sprintf( tmp, "Server-%d.csr", (int) time(0));
				
				cout <<endl<< "\tEnter filename for Server Certificate Sign Request [" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp );
				if ( in.substr( in.length() - 4 ) != ".csr" ) in.append( ".csr" );

				cout << "\twrite Cert. Sign Req. " << SSL_dir << in << " : " << (rc = ossl.writeCSR( in.c_str())) <<endl;
		
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '3' : {
				string in;

				string cakey = selectKeypair( "\tSelect Signing Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout <<endl<< "\t init Cert Sign Req.: " << ( rc =  initCSR( 1, in, ossl )) <<endl;
				cout <<endl<< "\tCSR signature-length: " << ( rc =  CSRQuery( in, ossl )) <<endl;
				if ( rc < 1 ) { cout <<endl; break; }

				cout <<endl;
				
				if ( log_level > LOG_ERR) ossl.writeCSR();
				
				char tmp[64];
				sprintf( tmp, "Client-%d.csr", (int) time(0));
				
				cout <<endl<< "\tEnter filename for Client Certificate Sign Request [" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp );
				if ( in.substr( in.length() - 4 ) != ".csr" ) in.append( ".csr" );

				cout << "\twrite Cert. Sign Req. " << SSL_dir << in << " : " << (rc = ossl.writeCSR( in.c_str())) <<endl;
		
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '4' : {
				string in;

				string cakey = selectKeypair( "\tSelect Signing Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout <<endl<< "\t init Cert Sign Req.: " << ( rc =  initCSR( 2, in, ossl )) <<endl;
				cout <<endl<< "\tCSR signature-length: " << ( rc =  CSRQuery( in, ossl )) <<endl;
				if ( rc < 1 ) { cout <<endl; break; }
				
				cout <<endl;
				
				if ( log_level > LOG_ERR) ossl.writeCSR();
				
				char tmp[64];
				sprintf( tmp, "IA-%d.csr", (int) time(0));
				
				cout <<endl<< "\tEnter filename for IA Certificate Sign Request [" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp );
				if ( in.substr( in.length() - 4 ) != ".csr" ) in.append( ".csr" );
				
				cout << "\twrite Cert. Sign Req. " << SSL_dir << in << " : " << (rc = ossl.writeCSR( in.c_str())) <<endl;
		
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case 'r' : {
				return;
				break;
			}

			case 'q' : {
				goodbye();
				break;
			}

			default : {
					cout <<endl <<"\tERROR: Wrong option!? Try again: " << role[0] <<endl<<endl;
			}
		}
	}		
}

void CAMenu() {

	OSSLCA ossl( log_level, SSL_dir );
				
	while ( true ) {
		
		ClearScreen();

		char role[64];
		
		cout <<"\tCertificate Authority Functions: " <<endl<<endl;
		
		cout <<"\t\t1) Generate CA's Public/Private Keypair" <<endl;
		cout <<"\t\t2) Generate CA CSR (Intermediate CA)" <<endl;
		cout <<"\t\t3) Generate CA's Self-signed Root Certificate" <<endl<<endl;

		cout <<"\t\t4) Sign Certificate Request (CSR)" <<endl<<endl;
		
		cout <<"\t\t5) Verify Cert. Signature against CA Cert. pub. key." <<endl<<endl;

		cout <<"\t\t6) Revoke a certificate" <<endl;
		cout <<"\t\t7) Revert a revoked certificate" <<endl<<endl;

		cout <<endl<< "\t\tr) return to previouse menu" <<endl;
		cout             << "\t\tq) exit" <<endl<<endl<<endl<< "\t\t> ";
		
		cin >> role; cin.ignore( 256, '\n' );
		
		if ( strlen( role ) > 1 ) { ClearScreen(); cout <<endl<< "\tERROR: Wrong option: " << role <<endl; sleep(1); return; } //continue; }
		
		ClearScreen();

		switch ( role[0] ) {
		
			case '1' : { // Generate CA's Public/Private Keypair
				//OSSLCA ossl( log_level, SSL_dir );
				genKeypair( ossl );
				break;
			}

			case '2' : { // Generate CA CSR (Intermediate CA)
				//OSSLCA ossl( log_level, SSL_dir );
				string in;
				int rc;

				string cakey = selectKeypair( "\tSelect Signing Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout <<endl<< "\t init Cert Sign Req.: " << ( rc =  initCSR( 2, in, ossl )) <<endl;
				cout <<endl<< "\tCSR signature-length: " << ( rc =  CSRQuery( in, ossl )) <<endl;
				if ( rc < 1 ) { cout <<endl; break; }
				
				cout <<endl;
				
				if ( log_level > LOG_ERR) ossl.writeCSR();
				
				char tmp[64];
				sprintf( tmp, "IA-%d.csr", (int) time(0));
				
				cout <<endl<< "\tEnter filename for IA Certificate Sign Request [" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp );
				if ( in.substr( in.length() - 4 ) != ".csr" ) in.append( ".csr" );
				
				cout << "\twrite Cert. Sign Req. " << SSL_dir << in << " : " << (rc = ossl.writeCSR( in.c_str())) <<endl;
		
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '3' : { // Generate CA's Self-signed Root Certificate
				//OSSLCA ossl( log_level, SSL_dir );
				int rc;
				string in;

				string cakey = selectKeypair( "\tSelect Signing Keypair:" );
				if ( cakey == "" ) break;
				
				cout <<endl<< "\tread Keypair: " << ( rc = ossl.readKeypair( cakey.c_str())) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				int dur = 365;
				
				do { 
					cout <<endl<< "\tEnter Cert. valid days [" << dur << "]: "; getline ( cin, in );
					if( trim( in ).length() > 1 && isNumeric( in ) ) dur = atoi( in.c_str() );
					if ( dur > 1 && dur < 65000 ) break;
					cout <<endl<< "\tThe valid entry is from 1 to 65000!?" <<endl<<endl;
				} while ( true );
				
				cout <<endl<< "\t init Cert Sign Req.: " << ( rc =  initRootCACSR( in, ossl )) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout <<endl<< "\tCSR signature-length: " << ( rc =  CSRQuery( in, ossl )) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }
				
				cout << "\tmake Self-signed Certificate: " << ( rc = ossl.mkSelfsignedCert( dur )) <<endl;
				if ( rc == -1 ) { cout <<endl; break; }

				cout <<endl;
				
				if ( log_level > LOG_ERR) ossl.writeCertificate();
				
				char tmp[64];
				sprintf( tmp, "Self-signed-%d.crt", (int) time(0));
				
				cout <<endl<< "\tEnter file name for Self-signed certificate [" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp ); 
				
				if ( in.substr( in.length() - 4 ) != ".crt" ) in.append( ".crt" );
				
				cout <<endl<< "\twrite Certificate " << SSL_dir << in << " : " << ( rc = ossl.writeCertificate( in.c_str())) <<endl;
				
				in.insert( 0, "trusted/" );
				
				cout <<endl<< "\twrite Certificate " << SSL_dir << in << " : " << ( rc = ossl.writeCertificate( in.c_str())) <<endl;
				
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '4' : { // Sign CSR (Certificate sign request)
				//OSSLCA ossl( log_level, SSL_dir );
				int rc;
				string in;
				
				string cacert = selectCertificate( "\tSelect Signing CA Certificate:" );
				if ( cacert == "" ) break;
				
				cout <<endl<< "\t-----------------------------------------------------" <<endl;

				string cakey = selectKeypair( "\tSelect Associated Signing Keypair:" );
				if ( cakey == "" ) break;

				cout <<endl<< "\tread CA Keypair/Cert. (bundle): " << ( in = ossl.readCABundle_str( cacert.c_str(), cakey.c_str())) <<endl;
				if ( in != "OK" ) { //cout <<endl<< "\tERROR: Failed to read CA keypair/Cert. files" <<endl<<endl;
//					sleep( 2 );
					break;
				}
				
				cout <<endl<< "\t-----------------------------------------------------" <<endl;

				string cert = selectCSR ( "\tSelect Certificate Sign Request:" );
				if ( cert == "" ) break;
				
				cout <<endl<< "\tread CSR: " << ( rc = ossl.readCSR( cert.c_str())) <<endl;
				if ( rc < 0 ) {
					cout <<endl<< "\tERROR: Failed to load CSR file!?" <<endl<<endl;
//					sleep( 2 );
					break;
				}

				cout <<endl<< "\t-----------------------------------------------------" <<endl;

				int dur = 365;
				
				do { 
					cout <<endl<< "\tEnter Cert. valid days [" << dur << "]: "; getline ( cin, in );
					if( trim( in ).length() > 1 && isNumeric( in ) ) dur = atoi( in.c_str() );
					if ( dur > 1 && dur < 65000 ) break;
					cout <<endl<< "\tThe valid entry is from 1 to 65000!?" <<endl<<endl;
				} while ( true );				

				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				ClearScreen();
				
				cout <<endl<< "\tSigning Certificate for " << dur << " days: " << ( rc = ossl.mkCert( dur )) <<endl<<endl;
				if ( rc < 1 ) {
					cerr <<endl<< "\tERROR: Failed to make certificate!?" << endl;
//					sleep( 2 );
					break;
				}
				
				//cout <<endl<< "\tappenCACert: " << ossl.appendCACert() << endl<<endl;
				
				cout <<endl<< "\t-----------------------------------------------------" <<endl<<endl;

				cout << "\t Issuer: " << ossl.certIssuer() << endl;
				cout << "\tSubject: " << ossl.certSubject() << endl;
				cout << "\tSubject hash: " << ossl.certSubjectHash() << endl<<endl;
				cout << "\t     Issue date: " << formattedGMTTime( ossl.certIssueTime()) <<endl;
				cout << "\texpiration date: " << formattedGMTTime( ossl.certExpireTime()) <<endl<<endl;
				cout << "\tCert. Version: " << ossl.certSerial() <<endl;
				cout << "\tCert.  Serial: " << ossl.certSerial() <<endl;
				cout << "\t  Is CA Cert.: " << ossl.isCACert_str() <<endl;
				cout << "\t  Self-signed: " << ossl.isSelfsignedCert() <<endl<<endl;
				
				cert = cert.substr ( 0, cert.length() -4 );
				char tmp[64];
				sprintf( tmp, "%s.crt", cert.c_str());
				
				cout <<endl<< "\tEnter the certificate's file name[" << tmp << "]: ";
				getline ( cin, in );
				
				if ( trim( in ).length() == 0 ) in = string ( tmp );
				if ( in.substr( in.length() - 4 ) != ".crt" ) in.append( ".crt" );
				
				cout << "\twrite Certificate: "  << SSL_dir << in << " : " << ( rc = ossl.writeCertificate( in.c_str())) <<endl;
		
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '5' : { // Verify Cert. Signature against CA Cert. pub. key.
				//OSSLCA ossl( log_level, SSL_dir );
				int rc;
				string in;
				
				string cacert = selectCACertificate( "\tSelect trusted CA Certificate:" );
				if ( cacert == "" ) break;
				
				cacert.insert( 0, "trusted/" );
				cout <<endl<< "\tread CA Certificate: " << ( rc = ossl.readCACert( cacert.c_str())) <<endl;
				if ( rc < 1 ) {
					cout <<endl<< "\tERROR: Failed to load CA certificate file!?" <<endl<<endl;
					cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
					break;
				}
				cout <<endl<< "\t-----------------------------------------------------" <<endl;
				
				string cert = selectCertificate ( "\tSelect Certificate to be verified:" );
				if ( cert == "" ) break;
				
				cout << "\tread Certificate: " << ( rc = ossl.readCertificate( cert.c_str())) <<endl;
				if ( rc < 1 ) {
					cout <<endl<< "\tERROR: Failed to load certificate file!?" <<endl<<endl;
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
					break;
				}
				
				cout <<endl<< "\t-----------------------------------------------------" <<endl;
				
				cout << "\t Issuer: " << ossl.certIssuer() << endl;
				cout << "\tSubject: " << ossl.certSubject() << endl;
				cout << "\tSubject hash: " << ossl.certSubjectHash() << endl<<endl;
				cout << "\t     Issue date: " << formattedGMTTime( ossl.certIssueTime()) <<endl;
				cout << "\texpiration date: " << formattedGMTTime( ossl.certExpireTime()) <<endl<<endl;
				cout << "\tCert. Version: " << ossl.certSerial() <<endl;
				cout << "\tCert.  Serial: " << ossl.certSerial() <<endl;
				cout << "\t  Is CA Cert.: " << ossl.isCACert_str() <<endl;
				cout << "\t  Self-signed: " << ossl.isSelfsignedCert() <<endl<<endl;
				
				
				cout <<endl<< "\tVerify Cert: " << ossl.verifyCertByCACert_str( 0 ) << endl<<endl;
				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case '6' : { // Revoke certificate
			
				int val;
				string in, sn;
				
				cout <<endl<< "\tEnter Certificate's serial number: "; getline ( cin, sn );
				
				if ( trim(sn).length() < 1 || sn.length() > 10 || ! isNumeric( sn ) ) {
					cout <<endl<< "\twrong value entered!? " << sn <<endl;
					sleep( 2 );
					break;
				}

				unsigned int serial = atoi( sn.c_str() );
				char fname[64];
				sprintf( fname, "dbase/issued/%010u", serial );
				
				cout <<endl<< "\tloading certificate in database: " << SSL_dir << fname <<endl;
				cout <<endl<< "\tread Certificate: " << ( val = ossl.readCertificate( fname )) <<endl;
				
				if ( val < 1 )
					cout <<endl<< "\tERROR: reading certificate failes!?" <<endl;
				else {
				
					cout <<endl<< "\t-----------------------------------------------------" <<endl;
					
					cout << "\t Issuer: " << ossl.certIssuer() << endl;
					cout << "\tSubject: " << ossl.certSubject() << endl;
					cout << "\t     Issue date: " << formattedGMTTime( ossl.certIssueTime()) <<endl;
					cout << "\texpiration date: " << formattedGMTTime( ossl.certExpireTime()) <<endl<<endl;
					cout << "\tCert.  Serial: " << ossl.certSerial() <<endl;

					cout <<endl<<endl<< "\tRevoke the certificate (y/n)? "; getline ( cin, in );
					
					if ( trim( in ).length() < 1 || in != "y" )
						cout <<endl<<"\tCancelled!" <<endl<<endl;
					else				
						cout <<endl<< "\trevoke ceritifcate; date: " << formattedGMTTime( ossl.revokeCertificate( serial )) <<endl;
				}

				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}
			
			case '7' : { // Revert a revoked certificate
				
				int val;
				string in, sn;
				
				cout <<endl<< "\tEnter Certificate's serial number: "; getline ( cin, sn );
				
				if ( trim(sn).length() < 1 || sn.length() > 10 || ! isNumeric( sn ) ) {
					cout <<endl<< "\twrong value entered!? " << sn <<endl;
					sleep( 2 );
					break;
				}

				unsigned int serial = atoi( sn.c_str() );
				char fname[64];
				sprintf( fname, "dbase/revoked/%010u", serial );
				
				cout <<endl<< "\tsearching database for: " << SSL_dir << fname << "-*" <<endl;
				
				vector <string> files;
	
				files.push_back( "ls -b " + string( SSL_dir) + fname + "-*" );
				
				val = exec( files );
				
				if ( files.size() < 1 || files[0].find( "No such file or directory" ) != string::npos ) { 
					cout <<endl<< "\t"<< files[0] <<endl;
					cout <<endl<<endl<< "\tPress any key to continue... "; getline ( cin, in );
					break;
				}
				
				
				for ( int i = 0; i < files.size(); i ++ )
						stringReplace( files[i], string( SSL_dir) + "dbase/revoked/", "" );
						
				files.insert( files.begin(), "" );
		
				if ( files.size() > 2 ) { // Multiple file with same serial number
				
					do { 
						cout <<endl<< "\tMultiple Files matches same serial number !?: " <<endl<<endl;
						
						cout << "\t0) Cancel & Return" <<endl<<endl;
						
						for ( int i = 1; i < files.size(); i ++ )
							cout << "\t" << i << ") " << files[i] <<endl;
						
						cout <<endl<<endl<< "\t> "; getline ( cin, in );
						val = atoi( in.c_str() );
						
						if ( val < 0 || val > files.size() -1 ) {
							cout <<endl<< "\tERROR: Wrong option!? " << val <<endl;
							sleep( 2 );
							continue;
						}
						
						break;
						
					} while( true );
					
					if ( val == 0 ) cout <<endl<< "\tCanceled." <<endl;

				} else 
					val = 1; // only one file matches
						
				cout <<endl<< "\tselected file: " << files[ val ] <<endl;
				
				cout <<endl<< "\tread Certificate: " << ( val = ossl.readCertificate( ("dbase/revoked/" + files[ val ]).c_str())) <<endl;
				
				if ( val < 1 ) {
					cout <<endl<< "\tERROR: reading certificate failes!?" <<endl;
					sleep( 2 );
					break;
				}

				cout <<endl<< "\t-----------------------------------------------------" <<endl;
				
				cout << "\t Issuer: " << ossl.certIssuer() << endl;
				cout << "\tSubject: " << ossl.certSubject() << endl;
				cout << "\t     Issue date: " << formattedGMTTime( ossl.certIssueTime()) <<endl;
				cout << "\texpiration date: " << formattedGMTTime( ossl.certExpireTime()) <<endl<<endl;
				cout << "\tCert.  Serial: " << ossl.certSerial() <<endl;

				cout <<endl<<endl<< "\tRevert back the certificate (y/n)? "; getline ( cin, in );
				
				if ( trim( in ).length() < 1 || in != "y" )
					cout <<endl<<"\tCancelled!" <<endl<<endl;
				else {
					cout <<endl<< "\trevert ceritifcate: " << ossl.restoreRevoked( serial, (time_t) atoi( files[val].substr( files[val].find( "-" ) + 1 ).c_str())) <<endl;
				}

				cout <<endl<< "\tpress Enter to Continue... "; getline ( cin, in );
				break;
			}

			case 'r' : {
				return;
				break;
			}

			case 'q' : {
				goodbye();
				break;
			}

			default : {
					cout <<endl <<"\tERROR: Wrong option!? Try again: " << role[0] <<endl<<endl;
			}
		}
	}	
}

void genKeypair( OSSLCert& ossl ) {

	while ( true ) {
		
		ClearScreen();
		
		char type[64];
		
		cout <<"\tSelect the Key type: " <<endl<<endl;
		
		cout <<"\t\t1) Generate ECC secp521r1 Keypair" <<endl;
		cout <<"\t\t2) Generate RSA F4 Keypair" <<endl<<endl;

		cout <<endl<<endl<< "\t\tr) return to previouse menu" <<endl;
		cout << "\t\tq) exit" <<endl<<endl<<endl<< "\t\t> ";
		
		cin >> type; cin.ignore( 256, '\n' );
		
		if ( strlen( type ) > 1 ) { ClearScreen(); cout <<endl<< "\tERROR: Wrong option: " << type <<endl; sleep(1); continue; }
		
		ClearScreen();
		
		switch ( type[0] ) {
		
			case '1' : {
				int rc;
				if ( rc == mkKeypair( 0, ossl ) ) { cout <<endl; break; }
				string in;
				cout <<endl<< "\tPress Enter to Continue..." <<endl; getline ( cin, in );
				return;
			}

			case '2' : {
				int rc;
				if ( rc == mkKeypair( 1, ossl ) ) { cout <<endl; break; }
				string in;
				cout <<endl<< "\tPress Enter to Continue..." <<endl; getline ( cin, in );
				return;
			}

			case 'r' : {
				return;
				break;
			}

			case 'q' : {
				goodbye();
				break;
			}

			default : {
				cout <<endl <<"\tERROR: Wrong option!? Try again: " << type <<endl<<endl;
				sleep( 2 );	
			}
		}
	}	
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main( int argc, char *argv[] )
{
    // Set Global Log level ERR, ThreadLog uses LOG_ALERT
    SysLog::setSysLogLevel(LOG_ERR);
    
	ClearScreen();
	
    cerr<<endl<< "\t... Version: " << Version << ", PID: " << getpid() <<endl; 

	//verify the system call is safe
	if ( ! system(NULL) ) 
	{
		cerr << "\tERROR: system() call is not available!?" <<endl<<endl;
		return -1;
	}
	
	cmdOpt *cmdopts = new cmdOpt( "hlf:" );

	if ( cmdopts->init(argc, argv) != 0) 
	{
		cerr<<endl<< "\tError: " << cmdopts->getErrors() <<endl <<endl;
		displayHelp(argv[0]);
		return -1;
	}

	if ( cmdopts->anyWarnings()) cerr<<endl<< "\tWarning: ignored unknown parameter(s)" << cmdopts->getWarnings() <<endl;

	if (cmdopts->isSet('l')) log_level = LOG_DEBUG;
	if (cmdopts->isSet('h')) { displayHelp(argv[0]); return 0; }
    if ( cmdopts->isSet('f') ) { 
		string dir = cmdopts->getValue('f');
		if ( dir[dir.length() - 1] != '/' ) dir.append( "/" );
		strcpy( SSL_dir, dir.c_str() );
	}

	cout <<endl<< "\t... config/database directory: " << SSL_dir <<endl;
	
	sleep(2);
	ClearScreen();
	
	MainMenu();

	exit(0);
}
