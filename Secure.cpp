//
//  Secure.cpp
//  KeyMgr
//
//  wrapper classes around openssl library, part of "an example programon using the Openssl library"
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

#include "Secure.h"

/* ***************************************************** *
 *  OSSL Class methods
 * ***************************************************** */
OSSL::OSSL( int logLvl, const char* SSL_dir ) {

	log_level = logLvl;

	tlog = make_unique<ThreadLog>( "OSSL", logLvl );

	ssl_dir = string( SSL_dir );
	if ( SSL_dir[strlen(SSL_dir) - 1 ] != '/' ) ssl_dir.append( "/" );
		
	fileWrapper fw( logLvl );
	
	if ( fw.init( ssl_dir ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir <<endl<<endl; exit(0); }
	
	if ( fw.init( ssl_dir + "private/" ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "private/" <<endl<<endl; exit(0); }
		
	if ( fw.init( ssl_dir + "trusted/" ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "private/" <<endl<<endl; exit(0); }

	/* --------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	
	trustycerts		= NULL;
	keypair = NULL;
	x509_req = NULL;
	certstack = NULL;
}

OSSL::~OSSL() {

	if (   	  trustycerts != NULL ) { X509_STORE_free( trustycerts ); 	trustycerts = NULL; }
	if (		  keypair != NULL ) { EVP_PKEY_free( keypair ); 		keypair = NULL; }
	if (         x509_req != NULL ) { X509_REQ_free( x509_req ); 		x509_req = NULL; }
	if (        certstack != NULL ) { sk_X509_INFO_pop_free( certstack, X509_INFO_free ); certstack = NULL; }

	CRYPTO_cleanup_all_ex_data();
	RAND_cleanup();
	EVP_cleanup();
	
	ERR_remove_thread_state(NULL);
	ERR_clear_error();
	
	ERR_free_strings();
    ERR_remove_state(0);
    ERR_remove_thread_state(NULL);
    
	CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
}

X509* OSSL::getStackItem( int idx) { //STACK_OF(X509_INFO) *& certstack, int idx ) {
	
	int cnt;
	if ( certstack == NULL || ( cnt = sk_X509_INFO_num( certstack )) < 1 || idx + 1 > cnt ) return NULL;
	
	X509_INFO* x509_cert = sk_X509_INFO_value( certstack, idx );
	
	if ( x509_cert->x509->signature->length < 1 ) return NULL;
	
	return x509_cert->x509;
}

BIO* OSSL::readBIO( const char* fname ) {
	
	BIO *fbio = NULL;
	
	fbio = BIO_new( BIO_s_file_internal());
	
	if( fbio == NULL ) {
		return NULL;
	}
	
	int rc;

	if ( ! ( rc = BIO_read_filename( fbio, fname ))) {
		if ( fbio != NULL ) BIO_free_all( fbio );
		return NULL;
	}
	
	return fbio;
}

BIO* OSSL::writeBIO( const char* fname ) {

	BIO *out = NULL;

	// BIO to print on file -or- Screen
	if ( fname == NULL )
		out = BIO_new_fp( stdout, BIO_NOCLOSE );
	else
		out = BIO_new_file( fname, "w" );

	return out;
}

string OSSL::to_hex_string( int value ) {
	
	ostringstream os;
    os << "0x" << setfill ('0') << std::setw(2) << std::hex << (int) value;
	
	return os.str();
}


int OSSL::initTrusties( const char* File, const char* Path ) {

	// MUST DONE THE COMMAND "c_rehash ." in the trusted directory.
	
	tlog->setPrefix( "initTrusties" );
	
	string cmd = "c_rehash " + ssl_dir + "trusted/";
	
	tlog->INFO( "cmd : " + cmd );
	tlog->INFO( "exec: " + to_string( exec( cmd, log_level )));
	
	int rc = -1;
	
	if ( 	trustycerts != NULL ) { X509_STORE_free( trustycerts ); trustycerts = NULL; }
	
	trustycerts = X509_STORE_new();
	
	if ( trustycerts == NULL ) {
		tlog->ERR( "ERROR: failed to create new X509 store." );
		return -1;
	}

	// X509_STORE_set_verify_cb() and X509_STORE_set_verify_cb_func() do not return a value
	X509_STORE_set_verify_cb( trustycerts, verify_callback );

	if ( Path != NULL ) tlog->INFO( "Path: " + string( Path ));
	if ( File != NULL ) tlog->INFO( "File: " + string( File ));

	rc = X509_STORE_load_locations( trustycerts, File, Path );
	
	if ( rc != 1 ) {
		tlog->ERR( "ERROR: failed to load CA certificates!?: " + to_string( rc ));
	}
	
	return rc;
}

int OSSL::addTrusty( const char * Trusty ) {

    tlog->setPrefix( "addTrusty" );

    if ( ! trustycerts ) {
		tlog->ERR( "cacert STORE is NULL!?" );
		return -1;
	}
	
	STACK_OF( X509_INFO ) *CACert = NULL;
	
	readCertificate( CACert, Trusty );
	
	int cnt = sk_X509_INFO_num( CACert ); 
	if ( cnt < 1 ) { tlog->ERR( "ERROR: No valid certificate: " + string( Trusty )); return -1; }

	int rc = 0;
	
	tlog->INFO( "num. of trusties in stack: " + to_string( cnt ));
					
	for ( int i = 0; i < cnt; i++) {
				
		X509_INFO* x509_cert = sk_X509_INFO_value( CACert, i );
		
		if ( ! x509_cert->x509 ) {
			tlog->INFO( "ERROR: " + to_string( i ) + ") no valid certificate" );
			continue;
		}
		
		if ( X509_check_ca( x509_cert->x509 ) < 1 ) {
			tlog->INFO( "Warning: Ordinary (non CA) Certificate ignored!" );
			continue;
		}
		
		if ( X509_STORE_add_cert( trustycerts, x509_cert->x509 ) == -1 ) {
			tlog->INFO( "ERROR: failed adding CA cert, i: " + to_string( i ));
			continue;
		}
		
		rc++;
	}

	if ( CACert != NULL ) sk_X509_INFO_pop_free( CACert, X509_INFO_free );
	
	return rc;
}

int OSSL::verifyCertByKeypair( X509* x509_cert, EVP_PKEY* Keypair ) {

	tlog->setPrefix( "verifyCertBykeypair" );
	
	if ( Keypair == NULL ) {
		tlog->ERR( "ERROR: keypais is not valid!?" );
		return -1;
	}
	
	if ( x509_cert == NULL ) {
		tlog->ERR( "ERROR: Cert is not valid!?" );
		return -1;
	}
	
	return X509_verify( x509_cert, Keypair );
}

int OSSL::isCACert ( int idx ) {

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL ) return -1;

	return isCACert( x509_cert );
}

int OSSL::isSelfsignedCert ( int idx ) {
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL ) return -1;

	return isSelfsignedCert( x509_cert );
}

int OSSL::isCACert( X509* x509_cert )			{ return X509_check_ca( x509_cert  ) > 0 ? 1 : 0; }
int OSSL::isSelfsignedCert( X509* x509_cert ) 	{ return X509_check_issued( x509_cert,  x509_cert ) == X509_V_OK ? 1 : 0; }

int OSSL::verifySelfsignedCert( X509* x509_cert ) {
	
	tlog->setPrefix( "verifySelfsignedCert" );

	if ( ! x509_cert ) {
		tlog->INFO( "ERROR: no x509 cert. to verify" );
		return -1;
	}
	
	int rc = 0;
	
	if ( X509_check_issued( x509_cert,  x509_cert ) != X509_V_OK ) {
		tlog->INFO( "Slef-Sign (root) Certificate: false;" );
		return -1;
	}

	EVP_PKEY *cert_pubkey = NULL;

	if ( ! ( cert_pubkey = X509_get_pubkey( x509_cert ))) {
		tlog->ERR( "ERROR: unpacking public key from Cert" );
		if ( cert_pubkey != NULL ) { EVP_PKEY_free( cert_pubkey ); cert_pubkey = NULL; }
		return -1;
	} 
	
	tlog->INFO( "Extract Cert's public key: OK" );

	if ( X509_verify( x509_cert, cert_pubkey ) != 1 ) {
		tlog->ERR( "ERROR: X509_verify Cert. signature" );
		if ( cert_pubkey != NULL ) { EVP_PKEY_free( cert_pubkey ); cert_pubkey = NULL; }
		return 0;
	}

	tlog->INFO( "Slef-Sign (root) Certificate: true;" );
	// self-signed certificates will always fails validation
	// validate self-signed certificates by adding them into a temporary store and then validating against it
	STACK_OF( X509 ) *certs = sk_X509_new_null();
				
	sk_X509_push( certs, x509_cert );
				
	X509_STORE *s = X509_STORE_new();
	int num = sk_X509_num( certs );
	X509 *top = sk_X509_value( certs, num-1);
	X509_STORE_add_cert(s, top);
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init( ctx, s, x509_cert, certs );

	ctx_verifyCertErro = X509_V_OK;
	
	rc = X509_verify_cert( ctx );
	ctx_verifyCertErro = X509_STORE_CTX_get_error( ctx );
	
	if ( rc < 1 ) {
		tlog->ERR( "ERROR:      X509_verify_cert rc: " + to_string( rc ));
		tlog->ERR( "ERROR: X509_STORE_CTX_get_error: " + to_string( ctx_verifyCertErro ));
		tlog->ERR( "ERROR: " + to_string( ctx_verifyCertErro ) + ") " + string( X509_verify_cert_error_string( ctx_verifyCertErro )));
	} else
		tlog->INFO( "X509_verify_cert (" + to_string( ctx_verifyCertErro ) + "): " + string( X509_verify_cert_error_string( ctx_verifyCertErro )));
		
exitVerifySelfsigned:

	if ( cert_pubkey != NULL ) EVP_PKEY_free( cert_pubkey );
	X509_STORE_CTX_cleanup( ctx );
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(s);
	sk_X509_free( certs );

	return rc;
}

int OSSL::verifyCertByTrusties( X509* x509_cert, bool processCA ) {

	tlog->setPrefix( "verifyCertByTrusties" );
	
	if ( ! x509_cert ) { //&& ! x509_cert->crl ) {
		tlog->INFO( "ERROR: no x509 cert. to verify" );
		return -1;
	}
	
	if ( X509_check_issued( x509_cert,  x509_cert ) == X509_V_OK ) {
		ctx_verifyCertErro = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
		tlog->INFO( "Slef-Sign (root) Certificate: true;" );
		tlog->ERR( "ERROR(" + to_string( ctx_verifyCertErro ) + "): X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN" );
		
		return 0;
	}

	//++ IS CA Certificate? ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	if ( X509_check_ca( x509_cert  ) > 0 )
		tlog->INFO( "CA certificate found." );
	
	int rc = 0;
	
	tlog->INFO( "Slef-Sign (root) Certificate: false;" );
	
	if ( ! trustycerts ) {
		tlog->ERR( "ERROR: cacert STORE is NULL!?" );
		return -1;
	}

	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if ( ! ctx ) {
		cerr <<endl<< "ERROR: failed to create STORE CTX" <<endl<<endl;
		return -1;
	}
					
	if ( X509_STORE_CTX_init( ctx, trustycerts, x509_cert, NULL) != 1 ) {	// NULL: STACK_OF(x509)* of chain of certificates to be verifed
		cerr << "ERROR: unable to initialize STORE CTX." <<endl<<endl;			// STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
		X509_STORE_CTX_free(ctx);
		return -1;
	}
		
	ctx_verifyCertErro = X509_V_OK;
	
	rc = X509_verify_cert( ctx );
	ctx_verifyCertErro = X509_STORE_CTX_get_error( ctx );
	
	if ( rc < 1 ) {
		tlog->ERR( "ERROR:      X509_verify_cert rc: " + to_string( rc ));
		tlog->ERR( "ERROR: X509_STORE_CTX_get_error: " + to_string( ctx_verifyCertErro ));
		tlog->ERR( "ERROR: " + to_string( ctx_verifyCertErro ) + ") " + string( X509_verify_cert_error_string( ctx_verifyCertErro )));
	} else
		tlog->INFO( "X509_verify_cert (" + to_string( ctx_verifyCertErro ) + "): " + string( X509_verify_cert_error_string( ctx_verifyCertErro )));
		
	X509_STORE_CTX_cleanup( ctx );
	X509_STORE_CTX_free(ctx);
	
	return rc;
}

int OSSL::readKeypair( EVP_PKEY*& Keypair, const char* fname, const char* PWD ) { 

	tlog->setPrefix( "readKeypair" );
	
	int rc = -1; 

	string FName = ssl_dir + "private/" + fname;
	BIO *in = readBIO( FName.c_str() );
	if ( in == NULL ) goto readKeypair;
		
	if ( Keypair != NULL ) { EVP_PKEY_free( Keypair ); Keypair = NULL; }
	
	if ( PWD != NULL ) {
		tlog->INFO( "PWD len: " + to_string( strlen( PWD )));
	} else {
		tlog->INFO( "password: NULL" ); 
	}

	if (! ( Keypair = PEM_read_bio_PrivateKey( in, NULL, 0, (void*) PWD ))) {
		tlog->ERR( "ERROR: reading keypair." );
		if ( Keypair != NULL ) { EVP_PKEY_free( Keypair ); Keypair = NULL; }
		goto readKeypair;
	}
			
	rc = 1;
	tlog->INFO( "read Keypair: OK" );
	
readKeypair:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: Reading failed!? " + string( FName ));

	BIO_free_all( in );
	
	return rc;	
}

int OSSL::readCSR( X509_REQ*& x509_Req, const char* fname ) {

	tlog->setPrefix( "readCSR" );
	
	int rc = -1; 

	string FName = ssl_dir + fname;
	BIO *in = readBIO( FName.c_str() );
	if ( in == NULL ) goto readCSR;
		
	if ( x509_Req != NULL ) { X509_REQ_free( x509_Req ); x509_Req = NULL; }
	
	if (! ( x509_Req = PEM_read_bio_X509_REQ( in, NULL, 0, NULL ))) {
		tlog->ERR( "ERROR: PEM_read_bio_X509_REQ" );
		goto readCSR;
	}
	
	rc = 1;
	tlog->INFO( "read CSR: OK" ); 
	
readCSR:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: Reading failed!? " + string( FName ) );

	BIO_free_all( in );
	
	return rc;	
}


int OSSL::readCertificate( STACK_OF(X509_INFO) *& CertStack, const char* fname ) {
	
	tlog->setPrefix( "readCertificate" );
	
	int rc = -1; 

	X509_INFO *stack_item = NULL;

	if (  CertStack != NULL ) { 
		tlog->INFO( "Warning: Cert. Stack was not empty, content deleted." );
		sk_X509_INFO_pop_free( CertStack, X509_INFO_free ); 
		CertStack = NULL; 
	}
	
	string FName = ssl_dir + fname;
	tlog->DEBUG( "=> FILE: " + FName );
	BIO *in = readBIO( FName.c_str() );
	if ( in == NULL ) goto readCertificate;
	
	CertStack = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	rc = sk_X509_INFO_num( CertStack );
	
	if( ! CertStack || rc < 1 ) {
		tlog->INFO( "ERROR: No certificate found!?" );
		goto readCertificate;
	}
	
	if ( ! ( stack_item = sk_X509_INFO_value( CertStack, 0 ) )) {
		tlog->INFO( "ERROR: sk_X509_INFO_value!?" );
		goto readCertificate;
	}
	
	if ( ! stack_item->x509 && ! stack_item->crl ) {
		tlog->INFO( "ERROR: unknown item returned by sk_X509_INFO_value" );
		rc = -1;
	}
	
	tlog->INFO( "read Certificate: OK, num. of cert: " + to_string( rc ));
	
readCertificate:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: Reading failed!? " + string( FName ) );

	BIO_free_all( in );

	return rc;	
}

int OSSL::readKeypair( const char* fname, const char* PWD )  { return readKeypair( keypair, fname, PWD ); }
int OSSL::readCSR( const char* fname ) 						 { return OSSL::readCSR( x509_req, fname ); }
int OSSL::readCertificate( const char* fname )				 { return OSSL::readCertificate( certstack, fname ); }

int OSSL::verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    ThreadLog tlog( "verify_callback", LOG_DEBUG ); // TODO set the loglevel of static method from global config
    // The list of ERRORs in man page
    // https://linux.die.net/man/3/x509_store_ctx_get_current_cert
    
    // http://stackoverflow.com/questions/20983217/how-to-display-the-subject-alternative-name-of-a-certificate
    // You get the X509* from a function like SSL_get_peer_certificate from a 
    // TLS connection, d2i_X509 from memory or PEM_read_bio_X509 from the filesystem.

    int depth = X509_STORE_CTX_get_error_depth( x509_ctx );
    int err = X509_STORE_CTX_get_error( x509_ctx );
    const char * errstr = X509_verify_cert_error_string( err );
		
    tlog.INFO( "preverify: " +to_string( preverify ) + ", Depth: " + to_string( depth ));
    tlog.INFO( "X509_STORE_CTX_get_error(" + to_string( err ) + ") " + errstr );
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
 
    char *line;
 
    if ( cert != NULL )
    {
        line = X509_NAME_oneline( iname, 0, 0 );
        tlog.DEBUG( " Issuer: " + string( line ));
        free(line);       // free the malloc'ed string
        
        line = X509_NAME_oneline( sname, 0, 0 );
        tlog.DEBUG( "Subject: " + string( line ));
        free(line);       // free the malloc'ed string
        
    } else
        tlog.INFO( "No certificate presented." );
    
    tlog.INFO( " " );
    
    // http://www.umich.edu/~x509/ssleay/x509_name.html
    tlog.DEBUG( " Issuer objects: " + to_string( X509_NAME_entry_count( iname )));
    tlog.DEBUG( "Subject objects: " + to_string( X509_NAME_entry_count( sname )));
    
    char NAME[512];
    
    tlog.DEBUG( "NID_commonName idx: ) " + to_string(NID_commonName));
    tlog.DEBUG( "NID_commonName len: ) " + 
            to_string( X509_NAME_get_text_by_NID( sname, NID_commonName, NAME, sizeof(NAME))));

    NAME[strlen(NAME)] = '\0';
    
    tlog.INFO( "NID_commonName: ) " + string(NAME));
    
    if(depth == 0) {
        // If depth is 0, its the server's certificate. Print the SANs too 
        print_san_name("Subject Alternative Name(san)", cert);
    }
    
	STACK_OF(X509)* chain = X509_STORE_CTX_get_chain( x509_ctx );
        
	tlog.INFO( "number of certs. in chain: " + to_string((int) sk_X509_num(chain)));
        
	X509* verified_cert = NULL;

	for (size_t i = 0; i < sk_X509_num(chain); ++i) {
		X509* cert = sk_X509_value(chain, i);
		if (i == 0) {
			tlog.INFO( "Verified index: " + to_string((int) i));
			verified_cert = cert;
		}
	}
    
    return preverify;
}


// http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.8+Adding+Hostname+Checking+to+Certificate+Verification/
int OSSL::verifyCertHostname(X509 *cert, char *hostname) {
    
    tlog->setPrefix( "spc_verify_cert_hostname" );
    
    int                   extcount, i, j, ok = 0;
    char                  certName[256];
    X509_NAME             *subj;
    const char            *extstr;
    CONF_VALUE            *nval;
    unsigned char         *data;
    X509_EXTENSION        *ext;
    X509V3_EXT_METHOD     *meth;
    STACK_OF(CONF_VALUE)  *val;
   
    if ((extcount = X509_get_ext_count(cert)) > 0) {
      
        for (i = 0;  !ok && i < extcount;  i++) {
        
            ext = X509_get_ext(cert, i);
            extstr = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
      
            if (!strcasecmp(extstr, "subjectAltName")) {
      
                if (!(meth = (X509V3_EXT_METHOD *) X509V3_EXT_get(ext))) break;
                data = ext->value->data;
   
                val = meth->i2v(meth, meth->d2i(0, (const unsigned char**) &data, ext->value->length), 0);
        
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++) {
          
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcasecmp(nval->name, "DNS") && !strcasecmp(nval->value, hostname)) {
                        ok = 1;
                        break;
                    } // if
                } // for
            } // if
        } // fot
    } // for
   
    if (!ok && (subj = X509_get_subject_name(cert)) &&
                X509_NAME_get_text_by_NID(subj, NID_commonName, certName, sizeof( certName )) > 0) {
        certName[sizeof( certName ) - 1] = '\0';

        tlog->DEBUG( "verify hostname \"" + string( hostname ) + "\" vs. cert. \"" + certName + "\"" );

        if (!strcasecmp(certName, hostname)) ok = 1;
    }
   
    return ok;
}

void OSSL::print_san_name(const char* label, X509* const cert)
{
    ThreadLog tlog( "print_san_name", LOG_DEBUG );

    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;

    do {
        if(!cert) break; // failed

        names = (GENERAL_NAMES*) X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;

        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; // failed 

        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;

            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;

                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }

                if(len1 != len2) {
                    //fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                    tlog.INFO( "Strlen and ASN1_STRING size do not match (embedded null?): " + to_string(len2) + " vs " + to_string(len1));
                }

                // If there's a problem with string lengths, then we skip the candidate and move on to the next.     
                // Another policy would be to fails since it probably indicates the client is under attack.              
                if(utf8 && len1 && len2 && (len1 == len2)) {

                    tlog.INFO( "  " + string(label) + ": " + string((char *)utf8));
                    success = 1;
                }

                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
                tlog.INFO( "  Unknown GENERAL_NAME type: " + to_string( entry->type ));
        }

    } while (0);

    if(names)
        GENERAL_NAMES_free(names);

    if(utf8)
        OPENSSL_free(utf8);

    if(!success)
        tlog.INFO( "  " + string( label ) + ": <not available>" );
}


/* ***************************************************** *
 *  OSSL Class methods
 * ***************************************************** */
OSSLCert::OSSLCert( int logLvl, const char* SSL_dir ) : OSSL( logLvl, SSL_dir ) {
	
	tlog = make_unique<ThreadLog>( "OSSL", logLvl );
	
	keypair    		= NULL;
	x509_req   		= NULL;
	x509_name  		= NULL;
	
	certstack  		= NULL;
	extensions 		= NULL;
	
	ctx 			= NULL;

	x509_crl		= NULL;
	revokedstack	= NULL;

	Ver 			= 2; // X509_REQ Version
	
}

OSSLCert::~OSSLCert() {

	if (		  keypair != NULL ) { EVP_PKEY_free( keypair ); 		keypair = NULL; }
	if (			  ctx != NULL ) { X509_STORE_CTX_free( ctx ); 		ctx = NULL; }
	if (         x509_req != NULL ) { X509_REQ_free( x509_req ); 		x509_req = NULL; }
	if (       extensions != NULL ) { sk_X509_EXTENSION_pop_free( extensions, X509_EXTENSION_free ); extensions = NULL; }
	if (        certstack != NULL ) { sk_X509_INFO_pop_free( certstack, X509_INFO_free ); certstack = NULL; }
	if (         x509_crl != NULL ) { X509_CRL_free( x509_crl ); 		x509_crl = NULL; }
}

int OSSLCert::mkRSAF4Keypair( int size )
{
	tlog->setPrefix( "mkRSAF4Keypair" );

	int status = 0;
	
	if ( keypair != NULL ) { EVP_PKEY_free( keypair ); keypair = NULL; }
	
	BIGNUM    *pBN = BN_new();
	RSA    *RSAkey = RSA_new();

	if ( BN_set_word( pBN, RSA_F4 ) != 1 ) {
		tlog->ERR( "ERROR: BN_set_word" );
		goto exitRSAKeys;
	}

	RAND_load_file("/dev/urandom", size );

	// Generate key
	RSA_generate_key_ex( RSAkey, size, pBN, NULL);
	if ( RSA_check_key( RSAkey ) != 1 ) {
		tlog->ERR( "ERROR: RSA_check_key" );
		goto exitRSAKeys;
	}

	tlog->INFO( "Size: " + to_string( size ) + " (bit)");
	tlog->INFO( "Type: " + to_string( RSA_F4 ));

	keypair = EVP_PKEY_new();

	// Convert RSA to PKEY
	if ( EVP_PKEY_set1_RSA( keypair, RSAkey ) != 1 ) {
		tlog->ERR( "ERROR: EVP_PKEY_set1_RSA" );
		goto exitRSAKeys;
	}

	status = 1;
	
exitRSAKeys:

	RSA_free ( RSAkey );
	BN_free( pBN );

	return status;
}

int OSSLCert::mkECCKeypair( const char *type )
{
	// http://fm4dd.com/openssl/eckeycreate.htm
	tlog->setPrefix( "mkECCKeypair" );

	int status = 0;

	if ( keypair != NULL ) { EVP_PKEY_free( keypair ); keypair = NULL; }
	
	keypair = EVP_PKEY_new();
	
	int      eccgrp;
	EC_KEY  *ecckey = NULL;
	EC_GROUP *ecgrp = NULL;

	/* ---------------------------------------------------------- *
	/* Create a EC key sructure, setting the group type from NID
	/* ---------------------------------------------------------- */
	eccgrp = OBJ_txt2nid( type );
	if ( eccgrp == NID_undef) {
		tlog->ERR( "ERROR: type not defined: " + string( type ));
		return -1;
	}
	
	EC_KEY_free( ecckey );
	
	ecckey = EC_KEY_new_by_curve_name( eccgrp );
	if ( ecckey == NULL ) {
		tlog->ERR( "ERROR: EC_KEY_new_by_curve_name" );
		return -1;
	}
	
	/* -------------------------------------------------------- *
	/* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag
	/* ---------------------------------------------------------*/
	// IMPORTANT: https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
	EC_KEY_set_asn1_flag( ecckey, OPENSSL_EC_NAMED_CURVE );

	/* -------------------------------------------------------- *
	/* Create the public/private EC key pair here
	/* ---------------------------------------------------------*/
	RAND_load_file("/dev/urandom", 2048);

	if ( ! ( EC_KEY_generate_key( ecckey ))) {
		tlog->ERR( "ERROR generating the ECC key." );
		goto exitRSAKeys;
	}

	/* -------------------------------------------------------- *
	/* Converting the EC key into a PKEY structure let us
	/* handle the key just like any other key pair.
	/* ---------------------------------------------------------*/
	if ( ! EVP_PKEY_assign_EC_KEY( keypair, ecckey )) {
		tlog->ERR( "ERROR assigning ECC key to EVP_PKEY structure." );
		goto exitRSAKeys;
	}
	/* -------------------------------------------------------- *
	/* Now we show how to extract EC-specifics from the key
	/* ---------------------------------------------------------*/
	ecckey = EVP_PKEY_get1_EC_KEY( keypair );
	ecgrp  = (EC_GROUP *) EC_KEY_get0_group( ecckey );

	/* ---------------------------------------------------------- *
	/* Here we print the key length, and extract the curve type.
	/* ---------------------------------------------------------- */
	tlog->INFO( "Size: " + to_string( EVP_PKEY_bits( keypair )) + " (bit)");
	tlog->INFO( "Type: " + string( OBJ_nid2sn( EC_GROUP_get_curve_name( ecgrp ))));

	status = 1;

exitRSAKeys:

	EC_KEY_free( ecckey );

	return status;
}

int OSSLCert::certVersion( int idx ) {

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	return X509_get_version( x509_cert );
}


int OSSLCert::certSerial( int idx ) {

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	return ASN1_INTEGER_get( X509_get_serialNumber( x509_cert ));
}

int OSSLCert::certIssueTime( int idx ) {
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	//++ Get Time +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	ASN1_TIME *cert_time = X509_get_notBefore( x509_cert );

	if ( ASN1_TIME_check( cert_time ) != 1 ) return (int) NULL;
	
	int days, secs;
	
	ASN1_TIME_diff( &days, &secs, cert_time, NULL );
	
	time_t t = time( 0 );
	
	return t - (( days * 24 * 60 * 60 ) + secs);
}	

int OSSLCert::certExpireTime( int idx ) {
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	//++ Get Time +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	ASN1_TIME *cert_time = X509_get_notAfter( x509_cert );

	if ( ASN1_TIME_check( cert_time ) != 1 ) return (int) NULL;
	
	int days, secs;
	
	ASN1_TIME_diff( &days, &secs, NULL, cert_time );
	
	time_t t = time( 0 );
	
	return t + (( days * 24 * 60 * 60 ) + secs);	
}

unsigned long OSSLCert::certSubjectHash( int idx ) {

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	return ( X509_NAME_hash( x509_cert->cert_info->subject ));
}

const string OSSLCert::certSubject( int idx ){

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return "";
	
	X509_NAME *SName = X509_get_subject_name( x509_cert );
	if ( ! SName ) return "";

	char *line;
	string str = string( ( line = X509_NAME_oneline( SName, 0, 0 )));
	
	free( line );

	return str;
}

const string OSSLCert::certIssuer( int idx ) {
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return "";
	
	
	X509_NAME *SName = X509_get_issuer_name( x509_cert );
	if ( ! SName ) return "";

	char *line;
	string str = string( ( line = X509_NAME_oneline( SName, 0, 0 )));
	
	free( line );

	return str;
}

int OSSLCert::verifyCACert( X509* x509_cacert ) {

	//++ IS CA Certificate? ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	int raw = X509_check_ca( x509_cacert  );
	
	if ( raw < 1 ) {
	
		tlog->INFO( "ERROR: object is not CA Certificate!?" );
		return 0;
	} else {
		
		if ( X509_check_issued( x509_cacert,  x509_cacert ) == X509_V_OK ) {

			tlog->INFO( "Slef-Sign root Certificate: true;" );
			//++ Validate self-signed CA certificate ++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
			// self-signed certificates will always fail
			//validate self-signed certificates by adding them into a temporary store and then validating against it
			STACK_OF( X509 ) *certs = sk_X509_new_null();
				
			sk_X509_push( certs, x509_cacert );
				
			X509_STORE *s = X509_STORE_new();
			int num = sk_X509_num( certs );

			X509 *top = sk_X509_value( certs, num-1);
			X509_STORE_add_cert(s, top);
			X509_STORE_CTX *ctx = X509_STORE_CTX_new();
			X509_STORE_CTX_init( ctx, s, x509_cacert, certs );

			if (X509_verify_cert(ctx) == 1) {
				tlog->INFO( "Validated OK." );
			} else {
				tlog->INFO( "ERROR: Validation failed." );
				int err = X509_STORE_CTX_get_error(ctx);
				tlog->INFO( getVerifyERRString( X509_STORE_CTX_get_error( ctx )));
				return -1;
			}

			X509_STORE_CTX_free(ctx);
			X509_STORE_free(s);
			sk_X509_free( certs );

		} else {
			tlog->INFO( "Slef-Sign root Certificate: false;" );
			return OSSL::verifyCertByTrusties( x509_cacert, false );
		}
		
	}

	//++ Get serial number +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	char serial_number[1001];

	ASN1_INTEGER *serial = X509_get_serialNumber( x509_cacert );
	BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
		
	if (!bn) {
		cerr << "unable to convert ASN1INTEGER to BN" <<endl<<endl;
		return EXIT_FAILURE;
	}

	char *tmp = BN_bn2dec(bn);
	if (!tmp) {
		cerr << "unable to convert BN to decimal string." <<endl<<endl;
		BN_free(bn);
		return EXIT_FAILURE;
	}

	if ( strlen(tmp) >= 1000 ) {
		cerr << "buffer length shorter than serial number" <<endl<<endl;
		BN_free(bn);
		OPENSSL_free(tmp);
		return EXIT_FAILURE;
	}

	cerr << "Serial(" << strlen( tmp ) << ") " << tmp <<endl;
		
	BN_free(bn);
	OPENSSL_free(tmp);
	
	//++ Get Time +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	ASN1_TIME *not_before = X509_get_notBefore( x509_cacert );
	ASN1_TIME *not_after = X509_get_notAfter( x509_cacert );

	// ANS1_TIME can be converted into ISO-8601 timestamps using the following code:
	BIO *b = BIO_new(BIO_s_mem());
	if (ASN1_TIME_print( b,  not_before ) <= 0) {
		cerr << "ASN1_TIME_print failed or wrote no data." <<endl<<endl;
		BIO_free(b);
		return EXIT_FAILURE;
	}
	
	#define DATE_LEN 128
	char buf [DATE_LEN];
	if ( BIO_gets(b, buf, DATE_LEN) <= 0) {
		cerr << "BIO_gets call failed to transfer contents to buf" <<endl<<endl;
		BIO_free(b);
		return EXIT_FAILURE;
	}
		
	BIO_free(b);
	cerr << "Valid from: " << buf <<endl;

	// ANS1_TIME can be converted into ISO-8601 timestamps using the following code:
	b = BIO_new(BIO_s_mem());
	if (ASN1_TIME_print( b,  not_after ) <= 0) {
		cerr << "ASN1_TIME_print failed or wrote no data." <<endl<<endl;
		BIO_free(b);
		return EXIT_FAILURE;
	}
		
	if ( BIO_gets(b, buf, DATE_LEN) <= 0) {
		cerr << "BIO_gets call failed to transfer contents to buf" <<endl<<endl;
		BIO_free(b);
		return EXIT_FAILURE;
	}
		
	BIO_free(b);
	cerr << "Expiration: " << buf <<endl;

	cout <<endl;
  
  return 1;
}

int OSSLCert::initServerCSR ( const char* CN ) {
	
	tlog->setPrefix( "initServerCert" );
	int rc;
	
	if (( rc = initCSR( CN )) != 1 ) return rc;
	
	if (( rc = CSR_KeyUsage( "critical,digitalSignature,Non Repudiation,keyEncipherment" )) != 1 ) return rc;
	if (( rc = CSR_Basic_Constraints( "CA:FALSE" )) != 1 ) return rc;
	if (( rc = CSR_Cert_Type( "server" )) != 1 ) return rc;

	return 1;
	
}

int OSSLCert::initClientCSR ( const char* CN ) {
	
	tlog->setPrefix( "initClientCert" );
	int rc;
	
	if (( rc = initCSR( CN )) != 1 ) return rc;
	
	if (( rc = CSR_KeyUsage( "critical,digitalSignature,Non Repudiation,keyEncipherment" )) != 1 ) return rc;
	if (( rc = CSR_Basic_Constraints( "CA:FALSE" )) != 1 ) return rc;
	if (( rc = CSR_Cert_Type( "client,email" )) != 1 ) return rc;
	
	return 1;
}

int OSSLCert::initCSR( const char* CN ) {

	// http://www.codepool.biz/how-to-use-openssl-to-generate-x-509-certificate-request.html
	
	tlog->setPrefix( "initCSR" );

	if (   x509_req != NULL ) { X509_REQ_free( x509_req ); x509_req = NULL; }
	if ( extensions != NULL ) { sk_X509_EXTENSION_pop_free( extensions, X509_EXTENSION_free ); extensions = NULL; }
	
    x509_req = X509_REQ_new();

	if ( keypair == NULL ) {
		tlog->ERR( "ERROR: EVP_PKEY == NULL" );
		return -1;
	}

	// set subject of x509 req
    x509_name = X509_REQ_get_subject_name( x509_req );

    if ( X509_REQ_set_pubkey( x509_req, keypair ) != 1 ) {
		tlog->ERR( "ERROR: X509_REQ_set_pubkey");
		return -1;
	} else
		tlog->INFO( "X509_REQ_set_pubkey: OK");
		
	if ( X509_REQ_set_version( x509_req, Ver ) != 1 ) {
		tlog->ERR( "ERROR: X509_REQ_set_version");
		return -1;
	} else
		tlog->INFO( "         Ver: " + to_string( Ver ));

	return CSR_addName( "CN", CN );
}

// TODO: Add parameter validity check
int OSSLCert::CSR_Country      ( const char* Val ) { tlog->setPrefix( "CSR_Country" ); 	return CSR_addName( "C", Val ); }
int OSSLCert::CSR_Province     ( const char* Val ) { tlog->setPrefix( "CSR_Province" ); return CSR_addName( "ST", Val ); }
int OSSLCert::CSR_City         ( const char* Val ) { tlog->setPrefix( "CSR_City" ); 	return CSR_addName( "L", Val ); }
int OSSLCert::CSR_Organization ( const char* Val ) { tlog->setPrefix( "CSR_Organization" ); return CSR_addName( "O", Val ); }
int OSSLCert::CSR_Email        ( const char* Val ) { tlog->setPrefix( "CSR_Email" ); 	return CSR_addName( "emailAddress", Val ); }

int OSSLCert::CSR_addName( const char* PAR, const char* value ) {

	if ( x509_req == NULL )	{
		tlog->ERR( "ERROR: CSR has not been initiated!?" );
		return -1;
	}
	
	tlog->INFO( string( value ));
			
	int status = X509_NAME_add_entry_by_txt( x509_name, PAR, MBSTRING_ASC, (const unsigned char*) value, -1, -1, 0 );
	
	if ( status <= 0 ) tlog->ERR( "ERROR: failure occured!?" );

	return status;
}

int OSSLCert::CSR_KeyUsage			( const char* Val ) { tlog->setPrefix( "CSR_KeyUsage" ); 			return CSR_addExtension( NID_key_usage, Val ); }
int OSSLCert::CSR_ExtKeyUsage		( const char* Val ) { tlog->setPrefix( "CSR_ExtKeyUsage" );			return CSR_addExtension( NID_ext_key_usage, Val ); }
int OSSLCert::CSR_SAN				( const char* Val ) { tlog->setPrefix( "CSR_SAN" );					return CSR_addExtension( NID_subject_alt_name, Val ); }
int OSSLCert::CSR_Basic_Constraints	( const char* Val ) { tlog->setPrefix( "CSR_Basic_Constraints" );	return CSR_addExtension( NID_basic_constraints, Val ); }
int OSSLCert::CSR_Cert_Type			( const char* Val ) { tlog->setPrefix( "CSR_Cert_Type" );			return CSR_addExtension( NID_netscape_cert_type, Val ); }
int OSSLCert::CSR_SSLServer_Name	( const char* Val ) { tlog->setPrefix( "CSR_SSLServer_Name" );		return CSR_addExtension( NID_netscape_ssl_server_name, Val ); }
int OSSLCert::CSR_Comment	( const char* Val ) { tlog->setPrefix( "CSR_Comment" );	return CSR_addExtension( NID_netscape_comment, Val ); }
int OSSLCert::CSR_CRL				( const char* Val ) { tlog->setPrefix( "CSR_CRL" );					return CSR_addExtension( NID_crl_distribution_points, Val ); }

int OSSLCert::CSR_addExtension( int nid, const char* value ) {
	
	tlog->setPrefix( "CSR_addExtension" );

	if ( x509_req == NULL )	{
		tlog->ERR( "ERROR: CSR has not been initiated!?" );
		return -1;
	}

	if ( extensions == NULL ) extensions = sk_X509_EXTENSION_new_null();
		
	X509_EXTENSION *ext = NULL;
	
	tlog->INFO( string( value ));
	
	ext = X509V3_EXT_conf_nid( NULL, NULL, nid, (char *) value );

	if ( ! ext ) {

		tlog->ERR( "ERROR: X509V3_EXT_conf_nid!?" );
		return -1;
	}

	sk_X509_EXTENSION_push( extensions, ext );

	return 1;
}

int OSSLCert::CSR_Custom_Ext ( const char* Oid, const char* ShortN, const char* LongN, const char* value ) { 
	
	tlog->setPrefix( "CSR_Custom_Ext" ); 
	
	if ( x509_req == NULL )	{
		tlog->ERR( "ERROR: CSR has not been initiated!?" );
		return -1;
	}

	if ( extensions == NULL ) extensions = sk_X509_EXTENSION_new_null();
		
	X509_EXTENSION *ext = NULL;
	
	int nid;

	tlog->INFO( "       oid: " + string( Oid ));
	tlog->INFO( "short name: " + string( ShortN ));
	tlog->INFO( " long name: " + string( LongN ));
	tlog->INFO( "     value: " + string( value ));
	
	nid = OBJ_create( Oid, ShortN, LongN );
	X509V3_EXT_add_alias( nid, NID_netscape_comment );
			
	// alternative way not showing here: 
	// https://www.mail-archive.com/openssl-users@openssl.org/msg65350.html
			
	if ( ! nid ) {
		tlog->ERR( "ERROR: nid NOT set!?" );
		return 0;
	}

	ext = X509V3_EXT_conf_nid( NULL, NULL, nid, (char *) value );

	if ( ! ext ) {

		tlog->ERR( "ERROR: X509V3_EXT_conf_nid!?" );
		return 0;
	}

	sk_X509_EXTENSION_push( extensions, ext );

	return 1;
}

int OSSLCert::mkCSR() {

	tlog->setPrefix( "mkCSR" );
	

	if ( x509_req == NULL )	{
		tlog->ERR( "ERROR: CSR has not been initiated!?" );
		return -1;
	}

	if ( extensions != NULL ) {
		
		tlog->INFO( "adding extensions" );
		// Now we've created the extensions we add them to the request
		X509_REQ_add_extensions( x509_req, extensions );
	}
	
    if ( X509_REQ_sign( x509_req, keypair, EVP_sha512()) <=0 ) { //EVP_sha256()) <= 0 ) {
		tlog->ERR( "ERROR: X509_REQ_sign" );
		return -1;
	}

	tlog->INFO( "Signature length : " + to_string( x509_req->signature->length ));
	
	return x509_req->signature->length;
}

int OSSLCert::CRT2CSR() {

	tlog->setPrefix( "CRT2CSR" );

	if ( keypair == NULL ) {
		tlog->ERR( "ERROR: EVP_PKEY == NULL" );
		return -1;
	}

	int cnt = sk_X509_INFO_num( certstack ); 
	if ( cnt < 1 ) { tlog->ERR( "ERROR: No certificate found!?" ); return -1; }
	
	tlog->INFO( "num. of stack_items: " + to_string( cnt ));
					
	X509_INFO* stack_item = sk_X509_INFO_value( certstack, 0 );
			
	if ( ! stack_item->x509 && ! stack_item->crl ) {
		tlog->INFO( "ERROR: unknown item returned by sk_X509_INFO_value" );
		return -1;
	}

	if ( stack_item->x509->signature->length < 1) {
		tlog->ERR( "ERROR: x509_req sign len not valid!??" );
		return -1;
	}

	int ver;
	X509_CINF *cert_info = NULL;
	STACK_OF( X509_EXTENSION ) *extensions;

	if (( x509_req = X509_to_X509_REQ( stack_item->x509, keypair, EVP_sha256() )) == NULL ) {
		tlog->ERR( "ERROR: X509_to_X509_REQ");
		return -1;
	}

	/* ----------------------------------------------------------- *
	/* Add X509V3 extensions                                       *
	/* ------------------------------------------------------------*/
	cert_info = stack_item->x509->cert_info;
	extensions =  cert_info->extensions;
	
	if ( extensions ) {
		tlog->ERR( "X509_REQ_get_extensions" );
		if( ( ver = X509v3_get_ext_count( extensions )) > 0 ) {
			
			tlog->INFO( "extensions: " + to_string( ver ));
			int loc;
			
			if ( ( loc = X509v3_get_ext_by_NID( extensions, NID_subject_key_identifier, -1 )) != -1 )
				X509_EXTENSION_free( X509v3_delete_ext( extensions, loc));
			
			if ( ( loc = X509v3_get_ext_by_NID( extensions, NID_authority_key_identifier, -1 )) != -1 )
				X509_EXTENSION_free( X509v3_delete_ext( extensions, loc));
			
			// NID_subject_key_identifier NID_authority_key_identifier
			// Now we've created the extensions we add them to the request
			X509_REQ_add_extensions( x509_req, extensions );
		} else if ( ver == 0 )
			tlog->INFO( "No extensions presents" );
		else {
			tlog->ERR( "ERROR: getting extensions" );
			return -1;
		}
	} else
		tlog->ERR( "X509_REQ_get_extensions: NULL" );

	ver = X509_get_version( stack_item->x509 );
	tlog->INFO( "Cert. ver: " + to_string( ver ));
	

	if ( X509_REQ_set_version( x509_req, ver ) != 1 )
		tlog->ERR( "ERROR: set version: " + to_string( ver ));
	else
		tlog->INFO( "CSR Ver: " + to_string( ver ));

    if ( X509_REQ_sign( x509_req, keypair, EVP_sha256()) <= 0 ) {
		tlog->ERR( "ERROR: X509_REQ_sign" );
		return -1;
	}

	tlog->INFO( "Signature length : " + to_string( x509_req->signature->length ));

	return x509_req->signature->length;
}

const char* OSSLCert::isCACert_str( int idx ) {

	switch( isCACert( idx )) {
		case -1: return "ERROR: An error occured!?"; break;
		case  0: return "Not a CA Cartificate"; break;
		case  1: return "X509v3 CA certificate"; break;
		case  3: return "self-signed X509 v1 certificate";  break;
		case  4: return "keyUsage extension bit keyCertSign (without basicConstraints!?)"; break;
		case  5: return "Netscape Type extension CA certificate"; break;
	}
}

int OSSL::verifyCertByTrusties( int idx ) {
	
	tlog->setPrefix( "verifyCertByTrusties" );
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;

	tlog->INFO( "verify Cert idx: " + to_string( idx ));

	return OSSL::verifyCertByTrusties( x509_cert );
}

int OSSL::verifyCertByKeypair( int idx ) {

	tlog->setPrefix( "verifyCertBykeypair" );
	
	if ( keypair == NULL ) {
		tlog->ERR( "ERROR: keypais is not loaded!?" );
		return -1;
	}
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	return X509_verify( x509_cert, keypair );
}

int OSSL::verifySelfsignedCert( int idx ) {

	tlog->setPrefix( "verifySelfsignedCert" );
	
	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;
	
	return OSSL::verifySelfsignedCert( x509_cert );
}

int OSSLCert::readCRL( const char* fname  ) {
	// usefull hists: /usr/include/openssl/x509.h
	tlog->setPrefix( "readCRL" );

	int rc = -1; 
	
	X509_NAME *SName;

	string FName = ssl_dir + fname;
	BIO *in = readBIO( FName.c_str() );
	if( in == NULL ) return -1;
	
	if ( x509_crl != NULL ) { 
		tlog->INFO( "WARNING: x509_crl is not empty!?" );
		X509_CRL_free( x509_crl ); 
		x509_crl = NULL; 
	}

	if ( ! PEM_read_bio_X509_CRL( in, &x509_crl, NULL, NULL )) {
		tlog->INFO( "ERROR: PEM_read_bio_X509_CRL." );
		goto exitreadCRL;
	}

	tlog->INFO( "Version: " + to_string( X509_CRL_get_version( x509_crl )));
	
	SName = X509_CRL_get_issuer( x509_crl );
	
	if ( ! SName ) {
		tlog->ERR( "Warning: getting CSR's subject name" );
	} else {
		char* line = X509_NAME_oneline( SName, 0, 0 );
		tlog->INFO( "Issuer SN: " + string( line ));
		free( line );
	}

	tlog->INFO( "extensions counts: " + to_string( X509_CRL_get_ext_count( x509_crl )));
	
	//rc = 1;
	rc = 0;
	
	if( (revokedstack = X509_CRL_get_REVOKED( x509_crl )) != NULL) 
		rc = sk_X509_REVOKED_num( revokedstack );
	
	if( rc > 0 ) {
		X509_REVOKED* x509_rv = sk_X509_REVOKED_value( revokedstack, 0 );
		
		x509_rv->serialNumber;
		x509_rv->revocationDate;
			
		int days, secs;
	
		ASN1_TIME_diff( &days, &secs, x509_rv->revocationDate, NULL );
	
		time_t t = time( 0 );
	}
	
exitreadCRL:

	(void)BIO_flush( in );
	BIO_free_all( in );
	
	return rc;	
}

int OSSLCert::readDERCRL( const char* fname  ) {

	tlog->setPrefix( "readDERCRL" );

	int rc = -1; 
	
	X509_NAME *SName;

	string FName = ssl_dir + fname;
	BIO *in = readBIO( FName.c_str() );
	if( in == NULL ) return -1;
	
	if ( x509_crl != NULL ) { 
		tlog->INFO( "WARNING: x509_crl is not empty!?" );
		X509_CRL_free( x509_crl ); 
		x509_crl = NULL; 
	}

		
	if ( ! d2i_X509_CRL_bio( in, &x509_crl )) {
		tlog->INFO( "ERROR: d2i_X509_CRL_bio." );
		goto exitreadDERCRL;
	}

	tlog->INFO( "Version: " + to_string( X509_CRL_get_version( x509_crl )));
	
	SName = X509_CRL_get_issuer( x509_crl );
	
	if ( ! SName ) {
		tlog->ERR( "Warning: getting CSR's subject name" );
	} else {
		char* line = X509_NAME_oneline( SName, 0, 0 );
		tlog->INFO( " Issuer SN: " + string( line ));
		free( line );
	}

	rc = 0;
	
	if( (revokedstack = X509_CRL_get_REVOKED( x509_crl )) != NULL) 
		rc = sk_X509_REVOKED_num( revokedstack );

exitreadDERCRL:
	
	(void)BIO_flush( in );
	BIO_free_all( in );
	
	return rc;	
}

int OSSLCert::writeKeypair( const char* fname, const char* PWD ) { 
	
	tlog->setPrefix( "writeKeypair" );

	int rc = -1; 
	
	/* ------------------------------------------------------------- *
	/* Here we print the private/public/CSR key data in PEM format.  *
	/* ------------------------------------------------------------- */
	string FName;
	BIO *out;
	
	if ( fname != NULL ) { 
		FName = ssl_dir + "private/" + fname;
		out = writeBIO( FName.c_str() );
	} else 
		out = writeBIO();

	if ( out == NULL ) goto exitWriteKeypair;

	// http://stackoverflow.com/questions/5927164/how-to-generate-rsa-private-key-using-openssl
	// PEM_write_bio_RSAPublicKey (PKCS PEM format). Notice BEGIN RSA PUBLIC KEY
	// PEM_write_bio_PUBKEY (Traditional PEM format). Notice BEGIN PUBLIC KEY
	// PEM_write_bio_PrivateKey (PEM). Notice BEGIN PRIVATE KEY
	// PEM_write_bio_PKCS8PrivateKey (PEM). Notice BEGIN PRIVATE KEY
	// PEM_write_bio_RSAPrivateKey (PEM). Notice BEGIN RSA PRIVATE KEY
	// i2d_RSAPublicKey_bio (ASN.1/DER)
	// i2d_RSAPrivateKey_bio (ASN.1/DER)
	
	if ( keypair == NULL ) { tlog->ERR( "ERROR: No keypair found!?" ); goto exitWriteKeypair; }
	
	if ( PWD != NULL ) {
		tlog->INFO( "PWD len: " + to_string( strlen( PWD )));
		tlog->INFO( "Encryption cipher: EVP_aes_256_cbc" ); 

		const EVP_CIPHER* pCipher = EVP_aes_256_cbc(); // EVP_des_ede3_cbc();

		if ( EVP_PKEY_type( EVP_PKEY_id( keypair )) == EVP_PKEY_EC ) {

			tlog->INFO( "Key type: ECC " );

		} else if ( EVP_PKEY_type( EVP_PKEY_id( keypair )) == EVP_PKEY_RSA ) {

			tlog->INFO( "Key type: RSA" );
		} else {
			tlog->ERR( "ERROR: Unknown key type!?" );
			goto exitWriteKeypair;
		}
				
		rc = PEM_write_bio_PKCS8PrivateKey(
			out,                  	// write the key to the file we've opened 
			keypair,               	// our key from earlier 
			pCipher, 				// default cipher for encrypting the key on disk 
			(char *) PWD,			// passphrase required for decrypting the key on disk 
			(int) strlen( PWD ),	// length of the passphrase string
			NULL,               	// callback for requesting a password 
			NULL                	// data to pass to the callback 
		);

	} else {
		tlog->INFO( "password: NULL" ); 
		rc = PEM_write_bio_PrivateKey( out, keypair, NULL, NULL, 0, 0, NULL );
	}

	
exitWriteKeypair:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: PEM_Write_bio_* failed!?" );
	else if( fname != NULL ) tlog->INFO( string( fname ));

	(void)BIO_flush( out );
	BIO_free_all( out );
	
	return rc;	
}



int OSSLCert::writePublicKey( const char* fname ) { 

	tlog->setPrefix( "writePublicKey" );

	int rc = -1; 
	
	/* ------------------------------------------------------------- *
	/* Here we print the private/public/CSR key data in PEM format.  *
	/* ------------------------------------------------------------- */
	string FName;
	BIO *out;
	
	if ( fname != NULL ) { 
		FName = ssl_dir + fname;
		out = writeBIO( FName.c_str() );
	} else 
		out = writeBIO();

	if ( out == NULL ) return rc;

	
	if ( keypair == NULL )
		tlog->ERR( "ERROR: No keypair found!?" );
	else
		rc = PEM_write_bio_PUBKEY( out, keypair ); 

	if ( rc == -1 ) tlog->ERR( "ERROR: PEM_Write_bio_* failed!?" );
	else if ( fname != NULL ) tlog->INFO( string( fname ));

	(void)BIO_flush( out );
	BIO_free_all( out );
	
	return rc;
}

int OSSLCert::writeCSR( const char* fname ) {
	
	tlog->setPrefix( "writeCSR" );

	int rc = -1; 
	
	/* ------------------------------------------------------------- *
	/* Here we print the private/public/CSR key data in PEM format.  *
	/* ------------------------------------------------------------- */
	string FName;
	BIO *out;
	
	if ( fname != NULL ) { 
		FName = ssl_dir + fname;
		out = writeBIO( FName.c_str() );
	} else 
		out = writeBIO();

	if ( out == NULL ) return -1;
	
	if ( x509_req == NULL )
		tlog->ERR( "ERROR: No CSR found!?" );
	else	
		rc = PEM_write_bio_X509_REQ( out, x509_req ); 
	
writeCSR:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: PEM_Write_bio_* failed!?" );
	else if ( fname != NULL ) tlog->INFO( string( fname ));

	(void)BIO_flush( out );
	BIO_free_all( out );
	
	return rc;
}


int OSSLCert::passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
	
    if(unPass > (size_t)size)
        unPass = (size_t)size;
		
    memcpy(pcszBuff, pPass, unPass);
	
    return (int)unPass;
}


/* ************************************************************************************************************************* *
 *  OSSLCA Class methods
 * ************************************************************************************************************************* */
OSSLCA::OSSLCA( int logLvl, const char* SSL_dir ) : OSSLCert( logLvl, SSL_dir ) {
	
	tlog = make_unique<ThreadLog>( "OSSL", logLvl );
	
	CAsign_certs 	= NULL;
	CAsign_EVPkey	= NULL;
	
	CRLVer 			= 1;

	serialNumber 	= 1;
	CRLNumber 		= 1;
	CRLUri			= "";
	
	ssl_dir = string( SSL_dir );
	if ( SSL_dir[strlen(SSL_dir)-1] != '/' ) ssl_dir += "/";

	tlog->INFO( "sslBase directory: " + ssl_dir );
	
	fileWrapper fw( logLvl );
	
	if ( fw.init( string( ssl_dir ) + "dbase/issued/" )  != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "dbase/issued/"  <<endl<<endl; exit(0); }
	
	if ( fw.init( string( ssl_dir ) + "dbase/revoked/" ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "dbase/revoked/" <<endl<<endl; exit(0); }
	
	if ( fw.init( string( ssl_dir ) + "dbase/expired/" ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "dbase/expired/" <<endl<<endl; exit(0); }

	if ( fw.init( string( ssl_dir ) + "dbase/CRL/" ) != 200 ) 
		if ( fw.mkDir() != 201 ) { cerr <<endl<< "\tERROR: failed to create: " << ssl_dir << "dbase/CRL/" <<endl<<endl; exit(0); }

	if ( fw.init( string( ssl_dir ) + "dbase/CRLUri.info" ) != 200 ) {
		tlog->ERR( "Warning: CRLUri.info file not found." );
	} else {
		if ( getCRLUri( CRLUri ) != 1 ) tlog->ERR( "Warning: Failed to get the CA CRL URI from dbase/CRLUri.info!?" );
	}

	if ( getSerialNumber( serialNumber ) != 1 ) tlog->ERR( "Warning: Failed to get the CA serial number from dbase!?" ); 
	if (    getCRLNumber(    CRLNumber ) != 1 ) tlog->ERR( "Warning: Failed to get the CA CRL number from dbase!?" ); 
		
	if ( serialNumber > 4294967295 ) 	{ tlog->ERR( "CA Serial Number exceeding the limit!?" ); exit(0); }
	if ( CRLNumber > 4294967295 ) 		{ tlog->ERR( "CA CRL Number exceeding the limit!?" ); exit(0); }

	tlog->INFO( " CA serial number: " + to_string( serialNumber ));// = 0; // "0_000_000_000"; // 4,294,967,295
	tlog->INFO( "    CA CRL number: " + to_string( CRLNumber ));// = 0; // "0_000_000_000"; // 4,294,967,295
}

OSSLCA::~OSSLCA() {

	if (	CAsign_EVPkey != NULL ) { EVP_PKEY_free( CAsign_EVPkey ); 	CAsign_EVPkey = NULL; }
	if (     CAsign_certs != NULL ) { sk_X509_INFO_pop_free( CAsign_certs, X509_INFO_free ); CAsign_certs = NULL; }
}

int OSSLCA::getSerialNumber( uint64_t& sn ) {
	
	string cmd = "ls -b " + ssl_dir + "dbase/issued/ | tail -1";
	cmd = s_exec( cmd );

	tlog->INFO( "CA serial number str(" + to_string( cmd.length()) + "): " + cmd );// = 0; // "0_000_000_000"; // 4,294,967,295

	if ( cmd.length() > 0 && isNumeric( cmd ) ) {
		sn = atol( cmd.c_str() );
		return 1;
	} else
		return 0;
}

int OSSLCA::getCRLNumber( uint64_t& CRLNum ) {

	string cmd = "ls -b " + ssl_dir + "dbase/CRL/ | tail -1";
	cmd = s_exec( cmd );

	tlog->INFO( "   CA CRL number str(" + to_string( cmd.length()) + "): " + cmd );// = 0; // "0_000_000_000"; // 4,294,967,295

	if ( cmd.length() > 0 && isNumeric( cmd ) ) {

		CRLNum = atol( cmd.c_str() ); 
		return 1;
	} else
		return 0;
}

int OSSLCA::getCRLUri( string& uri ) {

	string cmd = "cat " + ssl_dir + "dbase/CRLUri.info | head -1";
	trim ( cmd = s_exec( trim( cmd )));

	tlog->INFO( "      CA CRL URI str(" + to_string( cmd.length()) + "): " + cmd );

	if ( cmd.length() > 0 && cmd.find( "http://" ) == 0 ) {
		uri = "URI:" + cmd; 
		return 1;
	} else
		return 0;
}

int OSSLCA::initRootCACSR ( const char* CN ) {
	
	tlog->setPrefix( "initRootCACSR" );
	int rc;
	
	if (( rc = initCSR( CN )) != 1 ) return rc;
	
	if (( rc = CSR_KeyUsage( "critical, digitalSignature, cRLSign, keyCertSign, keyEncipherment" )) != 1 ) return rc;
	if (( rc = CSR_Basic_Constraints( "critical,CA:TRUE" )) != 1 ) return rc;

	return 1;
	
}

int OSSLCert::initCACSR ( const char* CN ) {
	
	tlog->setPrefix( "initCACSR" );
	int rc;
	
	if (( rc = initCSR( CN )) != 1 ) return rc;

	//if (( rc = CSR_KeyUsage( "critical, digitalSignature, cRLSign, keyCertSign,  keyEncipherment" )) != 1 ) return rc;
	if (( rc = CSR_KeyUsage( "critical, digitalSignature, cRLSign, keyCertSign" )) != 1 ) return rc;
	if (( rc = CSR_Basic_Constraints( "critical,CA:TRUE, pathlen:0" )) != 1 ) return rc;

	return 1;
	
}

int OSSLCA::writeCertificate( const char* fname ) {

	tlog->setPrefix( "writeCertificate" );

	int rc = -1; 
	
	/* ------------------------------------------------------------- *
	/* Here we print the private/public/CSR key data in PEM format.  *
	/* ------------------------------------------------------------- */
	string FName;
	BIO *out;
	
	if ( fname != NULL ) { 
		FName = ssl_dir + string( fname );
		out = writeBIO( FName.c_str() );
	} else 
		out = writeBIO();

	int cnt = sk_X509_INFO_num( certstack ); 
	if ( cnt < 1 ) { tlog->ERR( "ERROR: No certificate found!?" ); goto writeCertificate; }

	rc = 0;
	tlog->INFO( "Num. of stack_items: " + to_string( cnt ));
					
	for ( int i = 0; i < cnt; i++) {
				
		X509_INFO* x509_cert = sk_X509_INFO_value( certstack, i );
		
		if ( ! x509_cert->x509 ) { //&& ! x509_cert->crl ) {
			tlog->INFO( "ERROR: " + to_string( i ) + ") no valid certificate" );
			continue;
		}
		
		tlog->INFO( "Version: " + to_string( X509_get_version( x509_cert->x509 )));
		tlog->INFO( "Serial: " + to_string( ASN1_INTEGER_get( X509_get_serialNumber( x509_cert->x509 ))));

		X509_NAME *SName = X509_get_subject_name( x509_cert->x509 );
		if ( ! SName ) {
			tlog->ERR( "Warning: problem getting CSR's subject name" );
		} else {
			char* line = X509_NAME_oneline( SName, 0, 0 );
			tlog->INFO( " Issuer SN: " + string( line ));
			free( line );
		}
		
		if ( PEM_write_bio_X509( out, x509_cert->x509 ) == -1 ) {
			tlog->INFO( "ERROR:PEM_write_bio_X509, stack_item id: " + to_string( i ));
			continue;
		}
		rc++;
	}
			
	if ( rc == 0 ) rc = -1;
	
writeCertificate:
	
	if ( rc == -1 ) tlog->ERR( "ERROR: write failed!?" );
	else if ( fname != NULL ) tlog->INFO( string( fname ));

	(void) BIO_flush( out );
	BIO_free_all( out );
	
	return rc;	
}

int OSSLCA::writeCRL( const char* fname  ) {

	tlog->setPrefix( "writeCRL" );

	int rc = -1; 
	
	string FName;
	BIO *out;
	
	if ( fname != NULL ) { 
		FName = ssl_dir + fname;
		out = writeBIO( FName.c_str() );
	} else 
		out = writeBIO();

	rc = 0;
				
		
	if ( ! x509_crl ) {
		tlog->INFO( "ERROR: no valid CRL" );
		return -1;
	}
		
	tlog->INFO( "Version: " + to_string( X509_CRL_get_version( x509_crl )));
	
	X509_NAME *SName = X509_CRL_get_issuer( x509_crl );
	
	if ( ! SName ) {
		tlog->ERR( "Warning: getting CSR's subject name" );
	} else {
		char* line = X509_NAME_oneline( SName, 0, 0 );
		tlog->INFO( " Issuer SN: " + string( line ));
		free( line );
	}

	if ( PEM_write_bio_X509_CRL( out, x509_crl ) == -1 ) {
		tlog->INFO( "ERROR: PEM_write_bio_X509_CRL." );
	} else {
		if ( fname != NULL ) tlog->DEBUG( string( fname ));
		rc = 1;
	}

	(void)BIO_flush( out );
	BIO_free_all( out );
	
	return rc;	
}

int OSSLCA::writeDERCRL( const char* fname  ) {

	tlog->setPrefix( "writeDERCRL" );

	int rc = -1; 
	
	string FName;
	BIO *out;
	
	if ( fname == NULL ) { tlog->ERR( "ERROR: fname can not be NULL!?" ); return -1; } 
	FName = ssl_dir + string( fname );
	out = writeBIO( FName.c_str() );

	rc = 0;
				
		
	if ( ! x509_crl ) {
		tlog->INFO( "ERROR: no valid CRL" );
		return -1;
	}
		
	tlog->INFO( "Version: " + to_string( X509_CRL_get_version( x509_crl )));
	
	X509_NAME *SName = X509_CRL_get_issuer( x509_crl );
	
	if ( ! SName ) {
		tlog->ERR( "Warning: getting CSR's subject name" );
	} else {
		char* line = X509_NAME_oneline( SName, 0, 0 );
		tlog->INFO( " Issuer SN: " + string( line ));
		free( line );
	}

	if ( i2d_X509_CRL_bio( out, x509_crl ) == -1 ) {
		tlog->INFO( "ERROR: i2d_X509_CRL_bio." );
	} else {
		tlog->DEBUG( "OK" );
		rc = 1;
	}

	(void)BIO_flush( out );
	BIO_free_all( out );
	
	return rc;	
}

int OSSLCA::isExpired( const char* fname ) {

	if ( fname != NULL ) readCertificate( fname );

	if ( certstack == NULL ) { tlog->INFO( "ERROR: certstak is NULL!?" ); return -1; }
	
	int rc;
	
	if ( ( rc = isExpired()) == 1 ) {
		string str = "mv " + ssl_dir + string( fname ) + " " + ssl_dir + "dbase/expired/";
		exec( str, log_level );
	}
	
	return rc;
}

int OSSLCA::isExpired() {
	
	if ( certstack == NULL ) { tlog->INFO( "ERROR: certstak is NULL!?" ); return -1; }
	
	time_t Tm = time(0);

	tlog->INFO( "today: " + formattedGMTTime( Tm ));

	tlog->INFO( "cert. issued time: " + formattedGMTTime(  certIssueTime( 0 )));
	tlog->INFO( "cert. expire time: " + formattedGMTTime( certExpireTime( 0 )));
	
	if ( certExpireTime(0) < Tm ) { 
		return 1;
	} else
		return 0;
}

int OSSLCA::cleanExpiredCerts() {
	
	tlog->setPrefix( "cleanExpiredCerts" );
	
	int cnt = 0;
	
	vector <string> certs;

	certs.push_back( "ls -b " + ssl_dir + "dbase/issued/" );
	tlog->DEBUG( "exec: " + to_string( exec( certs, log_level )));
	tlog->DEBUG( "vec. size: " + to_string(  certs.size()));
		
	for ( int i = 0; i < certs.size(); i++ ) {

		string cert = "dbase/issued/" + certs[i];
		if ( isExpired( cert.c_str()) == 1 ) {
			tlog->INFO( "Cert. expired: " + cert );
			cnt++;
		}
	}
	
	return cnt;
}

int OSSLCA::mkCRL( int dur ) {
	// http://www.codepool.biz/how-to-use-openssl-to-generate-x-509-certificate-request.html
	
	tlog->setPrefix( "mkCRL" );
	
	int rc = -1;
	
	if ( x509_crl != NULL )	{ X509_CRL_free( x509_crl ); x509_crl = NULL; }

	if ( CAsign_certs == NULL || CAsign_EVPkey == NULL ) {
		tlog->INFO( "ERROR: No CA Cert/Keypair loaded.." );
		return -1;
	}

	time_t tm;
	
	X509_INFO *cacert = NULL;
	X509_NAME *subName = NULL;
	ASN1_TIME *Time = NULL;
	
	/*if ( certstack != NULL ) {
		int cnt = sk_X509_INFO_num( certstack ); 
		if ( cnt > 0 ) { 
			tlog->INFO( "Warning: certstack was not NULL, cnt: " + to_string( cnt ));
			sk_X509_INFO_pop_free( certstack, X509_INFO_free ); 
			certstack = NULL;
		}
	}*/
	
	/* -------------------------------------------------------- *
	/* Load signing CA Certificate file to get the Issuer SN
	/* ---------------------------------------------------------*/
	cacert = sk_X509_INFO_value( CAsign_certs, 0 );
	
	int raw = X509_check_ca( cacert->x509 );
		
	if ( raw < 1 ) {
		tlog->INFO( "ERROR: Provided Certificate is not a CA Cert. to sign the req.!?" );
		//goto exitmkCert;
		return -1;
	}
	
	tlog->DEBUG( "Is CA certificate; X509_check_ca: " + to_string( raw ) );
	
	if ( ! ( x509_crl = X509_CRL_new())) {
		tlog->ERR( "ERROR: X509_CRL_new!?" );
		goto exitmkCRL;
	}
		
	if ( X509_CRL_set_version( x509_crl, Ver ) != 1 ) {
		tlog->ERR( "ERROR: setting certificate version" );
		goto exitmkCRL;
	}

	tlog->DEBUG( "Version: " + to_string( X509_CRL_get_version( x509_crl )));

	/* --------------------------------------------------------- *
	/* Extract the subject name from the request                 *
	/* ----------------------------------------------------------*/
	subName = X509_get_subject_name( cacert->x509 );
	if ( ! subName ) {
		tlog->ERR( "ERROR: getting CSR's subject name" );
		goto exitmkCRL;
	} else {
		char* line = X509_NAME_oneline( subName, 0, 0 );
		tlog->INFO( "Subject SN: " + string( line ));
		free( line );
	}

	/* --------------------------------------------------------- *
	/* Set the CRL certificate's issuer name                     *
	/* ----------------------------------------------------------*/
	if ( X509_CRL_set_issuer_name( x509_crl, subName ) != 1 ) {
		tlog->ERR( "ERROR: setting Certificate subject name" );
		goto exitmkCRL;
	}
	
	/* --------------------------------------------------------- *
	/* Set the CRL certificate's time & issuer name              *
	/* ----------------------------------------------------------*/
	tm = time(0);
	
	if ( ( Time = ASN1_TIME_adj( NULL, tm, 0, 0)) == NULL ) {
		tlog->ERR( "ERROR: Failed to get adj time" );
		goto exitmkCRL;
	}
	
	if ( X509_CRL_set_lastUpdate( x509_crl, Time ) != 1 ) {
		tlog->ERR( "ERROR: X509_CRL_set_lastUpdate" );
		goto exitmkCRL;
	}
	
	if ( Time != NULL ) { ASN1_TIME_free( Time ); Time = NULL; }
	
	if ( ( Time = ASN1_TIME_adj( NULL, tm, dur, 0)) == NULL ) {  // hour, sec.
		tlog->ERR( "ERROR: Failed to get adj time" );
		goto exitmkCRL;
	}
	
	if ( X509_CRL_set_nextUpdate( x509_crl, Time ) != 1 ) {
		tlog->ERR( "ERROR: X509_CRL_set_nextUpdate" );
		goto exitmkCRL;
	}
	
	{
		// http://stackoverflow.com/questions/2883164/openssl-certificate-lacks-key-identifiers
		// http://openssl.6102.n7.nabble.com/Error-0x22073072-when-adding-SKI-to-CA-Cert-td48661.html
		// https://www.openssl.org/docs/manmaster/man3/X509_get_ext_d2i.html
		// https://www.openssl.org/docs/manmaster/man3/
		X509V3_CTX v3ctx;
		X509_EXTENSION *ext = NULL;
		
		X509V3_set_ctx( &v3ctx, cacert->x509, 0, 0, x509_crl, 0 ); 
			
		if ( ! ( ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, (char *) "keyid:always"))) { //"issuer:always,keyid:always" ))) { //"keyid:always"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_authority_key_identifier = keyid:always" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570912889 : openssl errstr 0x22077079 => V2I_AUTHORITY_KEYID:no issuer certificate
		} else { 
			X509_CRL_add_ext( x509_crl, ext, -1 );
			X509_EXTENSION_free( ext );
		}

		char sn[11];
		sprintf( sn, "%lu", CRLNumber );

		ASN1_OCTET_STRING *aserial = NULL;
		
		aserial = M_ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set( aserial, (unsigned char*) sn, strlen( sn ));
		//*/

		if ( ! ( ext = X509_EXTENSION_create_by_NID( NULL, NID_crl_number, 0, aserial ))) { //"issuer:always,keyid:always" ))) { //"keyid:always"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_crl_number = 4097" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570912889 : openssl errstr 0x22077079 => V2I_AUTHORITY_KEYID:no issuer certificate
		} else { 
			X509_CRL_add_ext( x509_crl, ext, -1 );
			X509_EXTENSION_free( ext );
		}
		
		if ( aserial != NULL) ASN1_OCTET_STRING_free( aserial );
	}
		
	/* --------------------------------------------------------- *
	/* Sign the certificate and verify cert. signature           *
	/* ----------------------------------------------------------*/
	tlog->INFO( "Sign certificate with CA's private key." );
	if ( X509_CRL_sign( x509_crl, CAsign_EVPkey, EVP_sha512()) <= 1) { //EVP_sha256() ) ) {
		tlog->ERR( "ERROR: signing the new certificate" );
		goto exitmkCRL;
	}
		
	if ( X509_CRL_verify( x509_crl, CAsign_EVPkey ) != 1 ) {
		tlog->ERR( "ERROR: X509_verify Cert" );
		goto exitmkCRL;
	}

	tlog->INFO( "X509_sign, digest EVP_sha512: OK" );

	if ( X509_CRL_set_version( x509_crl, CRLVer ) != 1 ) {
		tlog->ERR( "ERROR: X509_CRL_set_version");
		goto exitmkCRL;
	}
	
	tlog->INFO( "Ver: " + to_string( Ver ));

	/* ******************************************************* *
	 *  Adding revoked certificates CRL extensions
	 * ******************************************************* */
	{
		// get the list of r3evoked certificates
		vector <string> rvkd_certs;

		rvkd_certs.push_back( "ls -b " + ssl_dir + "dbase/revoked/" );
		tlog->DEBUG( "exec: " + to_string( exec( rvkd_certs, log_level )));
		tlog->DEBUG( "vec. size: " + to_string(  rvkd_certs.size()));
		
		// examine each cert. 
		for ( int i = 0; i < rvkd_certs.size(); i++ ) {

			string cert = "dbase/revoked/" + rvkd_certs[i];
			
			if ( isExpired( cert.c_str()) != 0 ) { 
				tlog->INFO( "Cert. ignored: " + cert );
				continue;
			}
			
			int loc = rvkd_certs[i].find( '-' );
			string SNum = rvkd_certs[i].substr( 0, loc );
			string RVTm = rvkd_certs[i].substr( loc + 1 );
			
			if( ! isNumeric( SNum ) || ! isNumeric( RVTm )) { tlog->ERR( "ERROR: Revoked Cert. ignored: " + rvkd_certs[i] ); continue; }
			tlog->INFO( "Revoked cert. SN: " + SNum + ", Rev. Time: " + RVTm );
			addRevokedCert( atol( SNum.c_str() ), atoi( RVTm.c_str() ));
		}
	}
	
	/* ******************************************************* *
	 *  Write CRL certs. PEM and DER disk files.
	 * ******************************************************* */
	{
		char FName[64];
		sprintf( FName, "dbase/CRL/%010lu", CRLNumber + 1 );
		if ( writeCRL( FName ) == 1 ) { 

			CRLNumber++;
		} else { 
			tlog->ALERT( "ERROR: Failed to write CRL: " + string( FName )); 
			goto exitmkCRL; 
		}
		
		sprintf( FName, "crl-certificate.der" );
		if ( writeDERCRL( FName ) != 1 ) { 
			tlog->ALERT( "ERROR: Failed to write CRL DER: " + string( FName ));
			goto exitmkCRL;
		}
	}
	
	rc = 1;
	
exitmkCRL:

	if ( Time != NULL ) { ASN1_TIME_free( Time ); Time = NULL; }
	
	return rc;
}

int OSSLCA::addRevokedCert( uint64_t SN, time_t tm ) {
	

	int rc = -1;
	
	if ( x509_crl == NULL ) {
		tlog->ERR( "ERROR: x509_crl is NULL" );
		return -1;
	}

	// https://www.openssl.org/docs/manmaster/man3/X509_CRL_add0_revoked.html
	X509_REVOKED *x509_rv_cert = NULL;
	x509_rv_cert = X509_REVOKED_new();
		
	ASN1_TIME *Time = NULL;

	/* --------------------------------------------------------- *
	/* Add Revoked certificate                                   *
	/* ----------------------------------------------------------*/
	ASN1_INTEGER *aserial = NULL;
		
	aserial = M_ASN1_INTEGER_new();
	ASN1_INTEGER_set( aserial, SN );
		
	if ( ! X509_REVOKED_set_serialNumber( x509_rv_cert, aserial )) {
		tlog->ERR( "ERROR: setting serial number of the certificate" );
		goto exitAddRevoked;
	}
		
	if ( aserial != NULL) ASN1_INTEGER_free( aserial );
		
	/*if ( ! ( sn = ASN1_INTEGER_get( X509_REVOKED_get0_serialNumber( x509_rv_cert )))) {
		tlog->ERR( "ERRO: validating certificate serial number" );
		goto exitAddRevoked;
	}

	tlog->DEBUG( "Serial: " + to_string( sn ) );*/
		

	if ( ( Time = ASN1_TIME_adj( NULL, tm, 0, 0)) == NULL ) {  // hour, sec.
		tlog->ERR( "ERROR: Failed to get adj time!?" );
		goto exitAddRevoked;
	}
	
	if ( ! X509_REVOKED_set_revocationDate( x509_rv_cert, Time )) {
		tlog->ERR( "ERROR: X509_REVOKED_set_revocationDate!?" );
		goto exitAddRevoked;
	}

	if ( ! X509_CRL_add0_revoked( x509_crl, x509_rv_cert )) { 
		tlog->ERR( "ERROR: X509_CRL_add0_revoked!?" );
		goto exitAddRevoked;
	}

	rc = 1;
	
exitAddRevoked:
	
	if ( Time != NULL ) { ASN1_TIME_free( Time ); Time = NULL; }
	
	return 1;
}

int OSSLCA::mkSelfsignedCert( int dur ) {

	tlog->setPrefix( "mkSelfsignedCert" );

	if ( x509_req == NULL ) {
		tlog->INFO( "ERROR: x509_req store is NULL!??" );
		return -1;
	}

	if ( x509_req->signature->length < 1) {
		tlog->ERR( "ERROR: x509_req sign len not valid!??" );
		return -1;
	}

	int ver, sn, raw;
	int rc = -1;
	
	EVP_PKEY *req_pubkey = NULL;
	ASN1_INTEGER *aserial = NULL;
	X509_NAME *subName, *issuName;
	
	STACK_OF( X509_EXTENSION ) *extensions = NULL;

	X509_INFO *cacert = NULL;

	if ( keypair == NULL ) {
		tlog->ERR( "ERROR: keypair stores are NULL!??" );
		return -1;
	}
		
	if ( certstack != NULL ) {
		int cnt = sk_X509_INFO_num( certstack ); 
		if ( cnt > 0 ) { 
			tlog->INFO( "Warning: certstack was not NULL, cnt: " + to_string( cnt ));
			sk_X509_INFO_pop_free( certstack, X509_INFO_free ); 
			certstack = NULL;
		}
	}

	if ( CAsign_certs != NULL ) {
		int cnt = sk_X509_INFO_num( CAsign_certs ); 
		if ( cnt > 0 ) { 
			tlog->INFO( "Warning: CAsign_certs was not NULL, cnt: " + to_string( cnt ));
			sk_X509_INFO_pop_free( CAsign_certs, X509_INFO_free ); 
			CAsign_certs = NULL;
		}
	}

	/* --------------------------------------------------------- *
	/* Build Certificate with data from request                  *
	/* ----------------------------------------------------------*/
	X509_INFO* x509_cert = X509_INFO_new();

	if ( ! ( x509_cert->x509 = X509_new() ) ) {
		tlog->ERR( "ERROR: X509_new" );
		goto exitmkSelfsignedCert;
	}
		
	tlog->INFO( "X509_new: OK" );

	ver = X509_REQ_get_version( x509_req );
	
	if ( X509_set_version( x509_cert->x509, ver ) != 1 ) {
		tlog->ERR( "ERROR: setting certificate version" );
		goto exitmkSelfsignedCert;
	}

	tlog->DEBUG( "Version: " + to_string( X509_get_version( x509_cert->x509 )));

	/* --------------------------------------------------------- *
	/* Extract the public key data from the request              *
	/* Use the public key to verify the signature    			 *
	/* ----------------------------------------------------------*/
	// http://stackoverflow.com/questions/16461720/how-to-use-x509-verify
	if ( ! ( req_pubkey = X509_REQ_get_pubkey( x509_req ))) {
		tlog->ERR( "ERROR: unpacking public key from CSR" );
		goto exitmkSelfsignedCert;
	} else
		tlog->INFO( "Extract CSR public key: OK" );

	if ( X509_REQ_verify( x509_req, req_pubkey ) != 1 ) {
		tlog->ERR( "ERROR: verifying signature on CSR" );
		goto exitmkSelfsignedCert;
	} else
		tlog->INFO( "CSR signature verify: OK" );

	/* --------------------------------------------------------- *
	/* set the certificate serial number here                    *
	/* If there is a problem, the value defaults to '0'          *
	/* ----------------------------------------------------------*/
	sn = 666;
	aserial = M_ASN1_INTEGER_new();
	
	ASN1_INTEGER_set( aserial, sn );
	
	if ( ! X509_set_serialNumber( x509_cert->x509, aserial ) ) {
		tlog->ERR( "ERROR: setting serial number of the certificate" );
		goto exitmkSelfsignedCert;
	}
	
	sn = -1;
	
	if ( ! ( sn = ASN1_INTEGER_get( X509_get_serialNumber( x509_cert->x509 )))) {
		tlog->ERR( "ERROR: getting certificate serial number" );
		goto exitmkSelfsignedCert;
	}

	tlog->DEBUG( "Serial: " + to_string( sn ) );

	/* --------------------------------------------------------- *
	/* Extract the subject name from the request                 *
	/* ----------------------------------------------------------*/
	subName = X509_REQ_get_subject_name( x509_req );
	if ( ! subName ) {
		tlog->ERR( "ERROR: getting CSR's subject name" );
		goto exitmkSelfsignedCert;
	} else {
		char* line = X509_NAME_oneline( subName, 0, 0 );
		tlog->INFO( "Subject SN: " + string( line ));
		free( line );
	}

	/* --------------------------------------------------------- *
	/* Set the new certificate subject/Issuer name               *
	/* ----------------------------------------------------------*/
	if ( X509_set_subject_name( x509_cert->x509, subName ) != 1 ) {
		tlog->ERR( "ERROR: setting Certificate subject name" );
		goto exitmkSelfsignedCert;
	}

	if ( X509_set_issuer_name( x509_cert->x509, subName ) != 1 ) {
		tlog->ERR( "ERROR: setting Certificate issuer name" );
		goto exitmkSelfsignedCert;
	}

	/* --------------------------------------------------------- *
	/* Set the new certificate public key
	/* ----------------------------------------------------------*/
	tlog->INFO( "Set certificate's public key." );

	if ( X509_set_pubkey( x509_cert->x509, req_pubkey ) != 1 ) {
		tlog->ERR( "ERROR: setting public key of certificate" );
		goto exitmkSelfsignedCert;
	}

	/* ---------------------------------------------------------- *
	/* Set X509V3 start date (now) and expiration date (+365 days)
	/* -----------------------------------------------------------*/
	tlog->INFO( "Set start date (now) and expiration date (days): +" + to_string( dur ));

	if ( ! ( X509_gmtime_adj( X509_get_notBefore( x509_cert->x509 ), 0 ) ) ) {
		tlog->ERR( "ERROR: setting start time" );
		goto exitmkSelfsignedCert;
	}

	if( ! ( X509_gmtime_adj( X509_get_notAfter( x509_cert->x509 ), ( dur * 24 * 3600 )))) {
		tlog->ERR( "ERROR: setting expiration time: " + to_string( dur ));
		goto exitmkSelfsignedCert;
	}

	/* ----------------------------------------------------------- *
	/* Add X509V3 extensions                                       *
	/* ------------------------------------------------------------*/
	extensions = X509_REQ_get_extensions( x509_req );

	if( ( ver = X509v3_get_ext_count( extensions )) > 0 ) {

		tlog->INFO( "num. of extensions: " + to_string( ver ));
		for( int i = 0; i < ver; i++ ) {

			X509_EXTENSION *ext;

			ext = sk_X509_EXTENSION_value( extensions, i );

			X509_add_ext( x509_cert->x509, ext, -1 );
		}
	} else if ( ver == 0 )
		tlog->INFO( "No extensions in CSR" );
	else
		tlog->ERR( "ERROR: getting extensions" );

	sk_X509_EXTENSION_pop_free( extensions, X509_EXTENSION_free );
	extensions = NULL;
	
	{
		// http://stackoverflow.com/questions/2883164/openssl-certificate-lacks-key-identifiers
		// http://openssl.6102.n7.nabble.com/Error-0x22073072-when-adding-SKI-to-CA-Cert-td48661.html
		X509V3_CTX v3ctx;
		X509_EXTENSION *ext = NULL;
		
		X509V3_set_ctx( &v3ctx, x509_cert->x509, x509_cert->x509, 0, 0, 0 );
			
		if ( CRLUri != "" ) {
			if ( ! ( ext = X509V3_EXT_conf_nid( NULL, &v3ctx, NID_crl_distribution_points, (char *) CRLUri.c_str() ))) {
				tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_crl_distribution_points." );
				tlog->ERR( "         CRL Url: http://www.geeks.dominion.com/server.der" );
				tlog->ERR( to_hex_string( ERR_get_error())); // 570896498 : openssl errstr 0x22073072 => S2I_SKEY_ID:no public key
			} else {
				tlog->INFO( "CRL: " + CRLUri );
				X509_add_ext( x509_cert->x509, ext, -1 );
				X509_EXTENSION_free( ext );
			}
		}

		if ( ! ( ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, (char *) "hash"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_subject_key_identifier = hash" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570896498 : openssl errstr 0x22073072 => S2I_SKEY_ID:no public key
		} else { 
			X509_add_ext( x509_cert->x509, ext, -1 );
			X509_EXTENSION_free( ext );
		}

		if ( ! (ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, (char *) "issuer:always,keyid:always" ))) { //"keyid:always"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_authority_key_identifier = keyid:always" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570912889 : openssl errstr 0x22077079 => V2I_AUTHORITY_KEYID:no issuer certificate
		} else { 
			X509_add_ext( x509_cert->x509, ext, -1 );
			X509_EXTENSION_free( ext );
		}
	}
	
	/* --------------------------------------------------------- *
	/* Sign the certificate and verify cert. signature           *
	/* ----------------------------------------------------------*/
	tlog->INFO( "Sign certificate with req.'s origin keypair." );

	if ( ! X509_sign( x509_cert->x509, keypair, EVP_sha256() ) ) {
		tlog->ERR( "ERROR: signing the new certificate" );
		goto exitmkSelfsignedCert;
	}

	if ( X509_verify( x509_cert->x509, keypair ) != 1 ) {
		tlog->ERR( "ERROR: X509_verify Cert" );
		goto exitmkSelfsignedCert;
	}

	tlog->INFO( "X509_sign, digest EVP_sha256: OK" );
	
	
	if(    certstack == NULL )    certstack = sk_X509_INFO_new_null();
	sk_X509_INFO_push(    certstack, x509_cert );

	/* --------------------------------------------------------- *
	/* Updating the dbase/issued & Serial number                 *
	/* ----------------------------------------------------------*/
	{
		char FName[64];
		sprintf( FName, "dbase/issued/%010lu", serialNumber + 1 );
		
		if ( writeCertificate( FName ) != 1 ) {
			tlog->ALERT( "ERROR: failed to write cert.: " + string( FName ));
			goto exitmkSelfsignedCert;
		} else
			serialNumber++;
	}

	rc = 1;
	
	x509_cert = NULL;
	
exitmkSelfsignedCert:

	/* ---------------------------------------------------------- *
	/* Free up all structures                                     *
	/* ---------------------------------------------------------- */
	tlog->DEBUG( "Free up structures." );
	M_ASN1_INTEGER_free( aserial );
	if ( req_pubkey != NULL ) { EVP_PKEY_free( req_pubkey ); req_pubkey = NULL; }
	if ( x509_cert != NULL ) { X509_INFO_free( x509_cert ); x509_cert = NULL; }
	
	return rc;
}

int OSSLCA::appendCACert() {

	tlog->setPrefix( "appendCACert" );

	if ( certstack == NULL ) {
		tlog->INFO( "ERROR: certstack store is NULL!??" );
		return -1;
	}

	if ( CAsign_certs == NULL ) {
			tlog->ERR( "ERROR: Signing CA cert. stack = NULL;" );
			return -1;
	}

	X509_INFO *cert = NULL;
	
	/* -------------------------------------------------------- *
	/* Adding IA certificate(s) to chain
	/* ---------------------------------------------------------*/
	int cnt = sk_X509_INFO_num( CAsign_certs ); 
	tlog->INFO( "num. of cert. in IA chain cert. stack: " + to_string( cnt ));
	
	for ( int i = 0; i < cnt; i++ ) 
	{
		
		cert = sk_X509_INFO_value( CAsign_certs, i );
		if ( cert == NULL ) {
			tlog->INFO( "WARNING: failed to add the CA cert. to the chain!?" );
			continue;
		}
		
		if ( ! cert->x509 ) {
			tlog->INFO( "WARNING: CA cert. in chain is not valid x509 cert!?" );
			continue;
		}
		
		if ( ! sk_X509_INFO_push( certstack, cert )) {
			tlog->INFO( "ERROR: sk_X509_INFO_push!?" );
			break;
		}
		
		cert = NULL;

	}
}

int OSSLCA::mkCert( int dur ) {

	tlog->setPrefix( "mkCert" );

	if ( x509_req == NULL ) {
		tlog->INFO( "ERROR: x509_req store is NULL!??" );
		return -1;
	}

	if ( x509_req->signature->length < 1) {
		tlog->ERR( "ERROR: x509_req sign len not valid!??" );
		return -1;
	}

	int ver, sn, raw;
	int cnt, rc = -1;
	
	EVP_PKEY *req_pubkey = NULL;
	ASN1_INTEGER *aserial = NULL;
	X509_NAME *subName, *issuName;
	
	STACK_OF( X509_EXTENSION ) *extensions = NULL;

	X509_INFO *cacert = NULL;

	if ( CAsign_certs == NULL || CAsign_EVPkey == NULL ) {
			tlog->ERR( "ERROR: Signing CA cert. and/or Key: = NULL;" );
			return -1;
	}

	if ( certstack != NULL ) {
		cnt = sk_X509_INFO_num( certstack ); 
		if ( cnt > 0 ) { 
			tlog->INFO( "Warning: certstack was not NULL, cnt: " + to_string( cnt ));
			sk_X509_INFO_pop_free( certstack, X509_INFO_free ); 
			certstack = NULL;
		}
	}
	
	/* -------------------------------------------------------- *
	/* Checking on signing Certificate is CA Cert.
	/* ---------------------------------------------------------*/
	cacert = sk_X509_INFO_value( CAsign_certs, 0 );
	
	raw = X509_check_ca( cacert->x509 );
	
	if ( raw < 1 ) {
		tlog->INFO( "ERROR: Provided Certificate is not a CA Cert. to sign the req.!?" );
		return -1;
	}
	
	tlog->DEBUG( "Is CA certificate; X509_check_ca: " + to_string( raw ) );

	/* --------------------------------------------------------- *
	/* Build Certificate with data from request                  *
	/* ----------------------------------------------------------*/
	X509_INFO* x509_cert = X509_INFO_new();

	if ( ! ( x509_cert->x509 = X509_new() ) ) {
		tlog->ERR( "ERROR: X509_new" );
		goto exitmkCert;
	}
		
	tlog->INFO( "X509_new: OK" );

	ver = X509_REQ_get_version( x509_req );
	
	if ( X509_set_version( x509_cert->x509, ver ) != 1 ) {
		tlog->ERR( "ERROR: setting certificate version" );
		goto exitmkCert;
	}

	tlog->DEBUG( "Version: " + to_string( X509_get_version( x509_cert->x509 )));

	/* --------------------------------------------------------- *
	/* Extract the public key from the request                   *
	/* And use the public key to verify the requests signature   *
	/* ----------------------------------------------------------*/
	// http://stackoverflow.com/questions/16461720/how-to-use-x509-verify
	if ( ! ( req_pubkey = X509_REQ_get_pubkey( x509_req ))) {
		tlog->ERR( "ERROR: unpacking public key from CSR" );
		goto exitmkCert;
	} else
		tlog->INFO( "Extract CSR public key: OK" );

	if ( X509_REQ_verify( x509_req, req_pubkey ) != 1 ) {
		tlog->ERR( "ERROR: verifying signature on CSR" );
		goto exitmkCert;
	} else
		tlog->INFO( "CSR signature verify: OK" );

	/* --------------------------------------------------------- *
	/* set the certificate serial number here                    *
	/* If there is a problem, the value defaults to '0'          *
	/* ----------------------------------------------------------*/
	aserial = M_ASN1_INTEGER_new();
	
	ASN1_INTEGER_set( aserial, serialNumber + 1 );
	
	if ( ! X509_set_serialNumber( x509_cert->x509, aserial ) ) {
		tlog->ERR( "ERROR: setting serial number of the certificate" );
		goto exitmkCert;
	}
	
	sn = -1;
	
	if ( ! ( sn = ASN1_INTEGER_get( X509_get_serialNumber( x509_cert->x509 )))) {
		tlog->ERR( "ERROR: getting certificate serial number" );
		goto exitmkCert;
	}

	tlog->DEBUG( "Serial Number: " + to_string( sn ) );

	/* --------------------------------------------------------- *
	/* Extract the subject name from the request                 *
	/* ----------------------------------------------------------*/
	subName = X509_REQ_get_subject_name( x509_req );
	if ( ! subName ) {
		tlog->ERR( "ERROR: getting CSR's subject name" );
		goto exitmkCert;
	} else {
		char* line = X509_NAME_oneline( subName, 0, 0 );
		tlog->INFO( "Subject SN: " + string( line ));
		free( line );
	}

	/* --------------------------------------------------------- *
	/* Set the new certificate subject name                      *
	/* ----------------------------------------------------------*/
	if ( X509_set_subject_name( x509_cert->x509, subName ) != 1 ) {
		tlog->ERR( "ERROR: setting Certificate subject name" );
		goto exitmkCert;
	}

	/* --------------------------------------------------------- *
	/* Extract the subject name from the signing CA cert         *
	/* -or- use the re. subject name as issuer name for 		 *
	/* self-signed certificates.								 *
	/* Set the new certificate issuer name                       *
	/* ----------------------------------------------------------*/
	issuName = X509_get_subject_name( cacert->x509 );
	if ( ! issuName ) {
		tlog->ERR( "ERROR: getting CSR's subject name" );
		goto exitmkCert;
	} else {
		char* line = X509_NAME_oneline( issuName, 0, 0 );
		tlog->INFO( " Issuer SN: " + string( line ));
		free( line );
	}
		
	if ( X509_set_issuer_name( x509_cert->x509, issuName ) != 1 ) {
		tlog->ERR( "ERROR: setting Certificate issuer name" );
		goto exitmkCert;
	}

	/* --------------------------------------------------------- *
	/* Set the new certificate public key
	/* ----------------------------------------------------------*/
	tlog->INFO( "Set certificate's public key." );
	if ( X509_set_pubkey( x509_cert->x509, req_pubkey ) != 1 ) {
		tlog->ERR( "ERROR: setting public key of certificate" );
		goto exitmkCert;
	}

	/* ---------------------------------------------------------- *
	/* Set X509V3 start date (now) and expiration date (+365 days)
	/* -----------------------------------------------------------*/
	tlog->INFO( "Set start date (now) and expiration date (days): +" + to_string( dur ));
	if ( ! ( X509_gmtime_adj( X509_get_notBefore( x509_cert->x509 ), 0 ) ) ) {
		tlog->ERR( "ERROR: setting start time" );
		goto exitmkCert;
	}

	if( ! ( X509_gmtime_adj( X509_get_notAfter( x509_cert->x509 ), ( dur * 24 * 3600 )))) {
		tlog->ERR( "ERROR: setting expiration time: " + to_string( dur ));
		goto exitmkCert;
	}

	/* ----------------------------------------------------------- *
	/* Add X509V3 extensions                                       *
	/* ------------------------------------------------------------*/
	extensions = X509_REQ_get_extensions( x509_req );

	if( ( ver = X509v3_get_ext_count( extensions )) > 0 ) {

		tlog->INFO( "num. of extensions: " + to_string( ver ));
		for( int i = 0; i < ver; i++ ) {

			X509_EXTENSION *ext;

			ext = sk_X509_EXTENSION_value( extensions, i );

			X509_add_ext( x509_cert->x509, ext, -1 );
		}
	} else if ( ver == 0 )
		tlog->INFO( "No extensions in CSR" );
	else
		tlog->ERR( "ERROR: getting extensions" );

	sk_X509_EXTENSION_pop_free( extensions, X509_EXTENSION_free );
	extensions = NULL;
	
	{
		// http://stackoverflow.com/questions/2883164/openssl-certificate-lacks-key-identifiers
		// http://openssl.6102.n7.nabble.com/Error-0x22073072-when-adding-SKI-to-CA-Cert-td48661.html
		X509V3_CTX v3ctx;
		X509_EXTENSION *ext = NULL;
		
		X509V3_set_ctx( &v3ctx, cacert->x509, x509_cert->x509, 0, 0, 0 ); 
			
		if ( ! ( ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, (char *) "hash"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_subject_key_identifier = hash" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570896498 : openssl errstr 0x22073072 => S2I_SKEY_ID:no public key
		} else { 
			X509_add_ext( x509_cert->x509, ext, -1 );
			X509_EXTENSION_free( ext );
		}

		if ( ! (ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, (char *) "issuer:always,keyid:always" ))) { //"keyid:always"))) {
			tlog->ERR( "WARNING: X509V3_EXT_conf_nid failed: NID_authority_key_identifier = keyid:always" );
			tlog->ERR( to_hex_string( ERR_get_error())); // 570912889 : openssl errstr 0x22077079 => V2I_AUTHORITY_KEYID:no issuer certificate
		} else { 
			X509_add_ext( x509_cert->x509, ext, -1 );
			X509_EXTENSION_free( ext );
		}
	}
	
	/* --------------------------------------------------------- *
	/* Sign the certificate and verify cert. signature           *
	/* ----------------------------------------------------------*/
	tlog->INFO( "Sign certificate with CA's private key." );
	if ( ! X509_sign( x509_cert->x509, CAsign_EVPkey, EVP_sha256() ) ) {
		tlog->ERR( "ERROR: signing the new certificate" );
		goto exitmkCert;
	}
		
	if ( X509_verify( x509_cert->x509, CAsign_EVPkey ) != 1 ) {
		tlog->ERR( "ERROR: X509_verify Cert" );
		goto exitmkCert;
	}

	tlog->INFO( "X509_sign, digest EVP_sha256: OK" );
	
	rc = 1;
	
	certstack = sk_X509_INFO_new_null();
	sk_X509_INFO_push( certstack, x509_cert );
	x509_cert = NULL;
	
	/* --------------------------------------------------------- *
	/* Updating the dbase/issued & Serial number                 *
	/* ----------------------------------------------------------*/
	{
		char FName[64];
		sprintf( FName, "dbase/issued/%010lu", serialNumber + 1 );
		tlog->DEBUG( "FNAME: " + string( FName ));
		
		if ( writeCertificate( FName ) != 1 ) {
			tlog->ALERT( "ERROR: failed to write cert.: " + string( FName ));
			goto exitmkCert;
		} else
			serialNumber++;
	}

	tlog->setPrefix( "mkCert" );
	
	rc = 1;
	
	/* -------------------------------------------------------- *
	/* Appending IA certificate(s) to chain
	/* ---------------------------------------------------------* /
	cnt = sk_X509_INFO_num( CAsign_certs ); 
	tlog->INFO( "num. of cert. in IA chain cert. stack: " + to_string( cnt ));
	
	for ( int i = 0; i < cnt; i++ ) 
	{
		
		X509_INFO *cert = sk_X509_INFO_value( CAsign_certs, 0 );
		if ( cert == NULL ) {
			tlog->INFO( "WARNING: failed to add the CA cert. to the chain!?" );
			continue;
		}
		
		if ( ! cert->x509 ) {
			tlog->INFO( "WARNING: CA cert. in chain is not valid x509 cert!?" );
			continue;
		}
		
		if ( ! sk_X509_INFO_push( certstack, cert )) {
			tlog->INFO( "ERROR: sk_X509_INFO_push!?" );
			break;
		}
		
		if (( cert = X509_INFO_new()) == NULL ) {
			tlog->INFO( "ERROR: X509_INFO_new!?" );
			break;
		}
		
		//X509_INFO_free( cert );
	} /* ** */
	
exitmkCert:

	/* ---------------------------------------------------------- *
	/* Free up all structures                                     *
	/* ---------------------------------------------------------- */
	tlog->DEBUG( "Free up structures." );
	if ( aserial    != NULL ) { M_ASN1_INTEGER_free( aserial ); aserial = NULL; }
	if ( req_pubkey != NULL ) { EVP_PKEY_free( req_pubkey ); req_pubkey = NULL; }
	if ( x509_cert  != NULL ) { X509_INFO_free( x509_cert );  x509_cert = NULL; }
	
	return rc;
}

const string OSSLCA::verifyCertByCACert_str	( int idx ) {

	switch( verifyCertByCACert( idx )) {
		case -1: { return "ERROR: An error occured!?"; break; }
		case  0: { return "X509V3 NOT SIGNED BY CA"; break; }
		case  1: {
			if ( isCACert( idx )) return "(1) X509v3 (CA) certificate: OK";
			else return "(1) X509v3 (Server/Client) certificate: OK";
			
			break;
		}
		case  2: return "(2) X509v3 CA Root (Self-signed) certificate: OK"; break;
	}
}
	
int OSSLCA::verifyCertByCACert( int idx ) {

	tlog->setPrefix( "verifyCertByCACert" );

	X509* x509_cert;
	if ( ( x509_cert = getStackItem( idx )) == NULL )  return -1;

	int ver, sn, raw;
	int rc = -1;
 
	X509_INFO *cacert = NULL;

	if ( CAsign_certs == NULL ) { //|| CAsign_EVPkey == NULL ) {
		tlog->ERR( "ERROR: CA Certificate store is NULL!?" ); 
		return -1; 
	}
	
	if ( CAsign_EVPkey != NULL ) {
		tlog->ERR( "CAsign Key store is not emplty, deleting content." ); 
		EVP_PKEY_free( CAsign_EVPkey );
	}
	
	cacert = sk_X509_INFO_value( CAsign_certs, 0 );
	
	raw = X509_check_ca( cacert->x509 );
	
	if ( raw < 1 ) {
		tlog->INFO( "ERROR: provided CA Certificate is not valid: "  + to_string( raw ));
		goto exitverifySignature;
	}
	
	tlog->DEBUG( "CA certificate? " + to_string( raw ) );
	
	/* ---------------------------------------------------------------- *
	/* Verify cetificate's signature                                    *
	/* -----------------------------------------------------------------*/
	if ( X509_check_issued( cacert->x509,  x509_cert )  != X509_V_OK ) {
		tlog->ERR( "ERROR: Certificate is not issued by CA" );
		rc = 0;
		goto exitverifySignature;
	}
	
	tlog->DEBUG( "Certificate issued by CA: OK" );

	CAsign_EVPkey = X509_get_pubkey( cacert->x509 );
	if ( CAsign_EVPkey == NULL ) {
		tlog->ERR( "ERROR: X509_get_pubkey failed on cacert!?" );
		goto exitverifySignature;
	}
	
	if ( X509_verify( x509_cert, CAsign_EVPkey ) != 1 ) {
		tlog->ERR( "ERROR: Cert. signature X509_verify failed!?" );
		rc = 0;
		goto exitverifySignature;
	}
	
	tlog->DEBUG( "X509_verify Cert signature: OK" );

	rc = 1;

	/* ------------------------------------------------------------------------ *
	/* Check if it is self-signed by checking cert. signature against itself    *
	/* ------------------------------------------------------------------------ */
	if ( X509_check_issued( x509_cert,  x509_cert )  == X509_V_OK ) {
		tlog->ERR( "Warning: Certificate is self-signed!?" );
		rc = 2;
	}
	
exitverifySignature:

	return rc;
}

int OSSLCA::readCACert( const char* CACert ) {
	
	if ( CAsign_certs != NULL ) { sk_X509_INFO_pop_free( CAsign_certs, X509_INFO_free ); CAsign_certs = NULL; }

	int rc = -1, cnt;
	
	X509_INFO *stack_item = NULL;
	
	cnt = OSSL::readCertificate( CAsign_certs, CACert );
	
	if ( cnt < 1 ) {
		tlog->ERR( "ERROR: Failed to read signing CA Certificate: " + string( CACert ));
		goto readCACert;
	}
	
	tlog->INFO( "Num. of Certs found: " + to_string( cnt ));

	if ( ! ( stack_item = sk_X509_INFO_value( CAsign_certs, 0 ) )) {
		tlog->INFO( "ERROR: sk_X509_INFO_value!?" );
		goto readCACert;
	}

	if ( X509_check_ca( stack_item->x509 ) < 1 ) {
		tlog->INFO( "ERROR: Not a CA Certificate: " + ssl_dir + string( CACert ));
		goto readCACert;
	}
	
	rc = cnt;
	
readCACert:

	return rc;
}

string OSSLCA::readCABundle_str( const char* CACert, const char* CAKey, const char* CAPWD ) {

	int rc = readCABundle( CACert, CAKey, CAPWD );
	
	switch ( rc ) {
		case 	 1: return "OK";
		case	-1: return "ERROR: An error Occured!?";
		case	-2: return "ERROR: failed to read CA Cert: " + string( CACert );
		case	-3: return "ERROR: Failed to read signing CA keypair: " + string( CAKey );
		case	-4: return "ERROR: sk_X509_INFO_value failed to get CA Cert from stack store!?";
		case	-5: return "ERROR: Unknown Key type!?";
		case	-7: return "ERROR: The CA Cert and Key are not associated!?";
		case	-8: return "ERROR: Failed to get RSA from CA Cert or Key!?";
		case	-9: return "ERROR: the key types of the CA Cert & CA key are different!?";
	}
}

int OSSLCA::readCABundle( const char* CACert, const char * CAKey, const char* CAPWD ) {
	
	if ( CAsign_EVPkey != NULL ) { EVP_PKEY_free( CAsign_EVPkey ); CAsign_EVPkey = NULL; }

	int rc = -1, cnt;
	
	if ( ( rc = readCACert( CACert )) < 1 ) {
		tlog->INFO( "ERROR: failed to read CA Cert: " + string( CACert ));
		rc = -2;
		goto readCABundle;
	}
	
	if ( OSSL::readKeypair( CAsign_EVPkey, CAKey, CAPWD ) < 1 ) {
		tlog->INFO( "ERROR: Failed to read signing CA keypair: " + string( CAKey ));
		rc = -3;
		goto readCABundle;
	}

	{
		
		X509_INFO *stack_item = NULL;
		
		if ( ! ( stack_item = sk_X509_INFO_value( CAsign_certs, 0 ) )) {
			tlog->INFO( "ERROR: sk_X509_INFO_value!?" );
			rc = -4;
			goto readCABundle;
		}
		
		// http://stackoverflow.com/questions/11651632/how-to-test-a-public-private-keypair-in-c
		// http://stackoverflow.com/questions/23176439/openssl-command-in-c-to-get-modulus-of-a-public-key-in-the-rsa
		EVP_PKEY *CAtemp;
		CAtemp = X509_get_pubkey( stack_item->x509 );
		
		int cakeyType  = EVP_PKEY_type( EVP_PKEY_id( CAsign_EVPkey ));
		int cacertType = EVP_PKEY_type( EVP_PKEY_id( CAtemp ));
		
		tlog->DEBUG( "CA Cert Key type: " + to_string ( cacertType ));
		tlog->DEBUG( "CA Pub. Key type: " + to_string (  cakeyType ));
		
		if ( cakeyType != cacertType ) {
			tlog->INFO( "ERROR: the key types of the CA Cert & CA key are different!?" );
			rc = -9;
		} else if ( cakeyType == EVP_PKEY_RSA ) {
			
			RSA* certRSA = EVP_PKEY_get1_RSA( CAtemp );
			RSA*  keyRSA = EVP_PKEY_get1_RSA( CAsign_EVPkey );
		
			if ( certRSA == NULL || keyRSA == NULL ) { 
				tlog->INFO( "ERROR: certRSA or keyRSA: NULL"); 
				rc = -8; 
			} else if ( BN_cmp( certRSA->n, keyRSA->n ) != 0 ) { 
				tlog->INFO( "ERROR: The CA Cert and Key are not associated!?" ); 
				rc = -7; 
			} else
				rc = 1;
			
			RSA_free( certRSA );
			RSA_free(  keyRSA );
			
		} else if ( cakeyType == EVP_PKEY_EC ) { 
		// https://commondatastorage.googleapis.com/chromium-boringssl-docs/evp.h.html#EVP_PKEY_cmp
		// maybe: http://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/

			if ( EVP_PKEY_cmp( CAtemp, CAsign_EVPkey ) != 1 ) {
				tlog->INFO( "ERROR: The CA Cert and Key are not associated!?" );
				rc = -7;
			} else
				rc = 1;
		} else {
			tlog->INFO( "ERROR: Unknown key type" );
			rc = -5;
		}
		
		EVP_PKEY_free( CAtemp );
	}
		
readCABundle:

	return rc;
}


int OSSLCA::revokeCertificate( uint64_t sn ) {

	tlog->setPrefix( "revokeCertificate" );
	
	fileWrapper fw( log_level );
	
	char fname[4096];
	sprintf( fname, "%sdbase/issued/%010lu", ssl_dir.c_str(), sn );
	
	tlog->INFO( "Cert. to revoke: " + string( fname ));
	
	if ( fw.init( fname ) != 200 ) { tlog->INFO( "ERROR: cert not found in issued folder!?" ); return -1; }
	
	time_t tm = time( 0 );
	sprintf( fname, "mv %sdbase/issued/%010lu %sdbase/revoked/%010lu-%d", ssl_dir.c_str(), sn, ssl_dir.c_str(), sn, (int) tm );
	
	tlog->INFO( fname );
	return exec( string( fname )) == 0 ?  (int) tm : -1;
}

int OSSLCA::restoreRevoked( uint64_t sn, time_t tm ) {
	
	tlog->setPrefix( "reValidateCertificate" );
	
	fileWrapper fw( log_level );
	
	char fname[1024];
	sprintf( fname, "%sdbase/revoked/%010lu-%d", ssl_dir.c_str(), sn, (int) tm );
	
	tlog->INFO( "Cert. to activate: " + string( fname ));
	
	if ( fw.init( fname ) != 200 ) { tlog->INFO( "ERROR: cert not found in revoked folder!?" ); return -1; }
	
	sprintf( fname, "mv %sdbase/revoked/%010lu-%d %sdbase/issued/%010lu", ssl_dir.c_str(), sn, (int) tm, ssl_dir.c_str(), sn );
	
	tlog->INFO( fname, log_level );
	return exec( string( fname )) == 0 ?  1 : -1;
}


