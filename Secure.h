//
//  Secure.h
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

#ifndef  __SECURE_H_INCLUDED__   // if header hasn't been defined yet...
#define __SECURE_H_INCLUDED__   //   #define this so the compiler knows it has been included

//Native Headers
#include "Auxiliary.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/asn1t.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <iomanip>			// setfill

using namespace std;

// Base64 stuff sample: http://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl
/* ************************************************************************************************ *
 *  OSSL Class
 * ************************************************************************************************ */
class OSSL
{
public:
	OSSL( int logLvl = LOG_ERR, const char* SSL_dir = "./ssl/" );
	~OSSL();

//	int mkRSAF4Keypair	( EVP_PKEY *&, int size = 2048 );
//	int mkECCKeypair	( EVP_PKEY *&, const char *type = "secp521r1" );

	int initTrusties	( const char* File = NULL , const char* Path = NULL );
	int addTrusty		( const char* );
	
	int readKeypair		( const char*, const char* PWD = NULL );
	int readCSR			( const char* );
	int readCertificate	( const char* );

	
	int isCACert			( X509* x509_cert );
	int isSelfsignedCert	( X509* x509_cert );

	int verifyCertByKeypair		( X509* x509_cert, EVP_PKEY* );
	int verifyCertByTrusties	( X509* x509_cert, bool processCA = false );
	int verifySelfsignedCert	( X509* x509_cert );

	int isCACert			( int idx = 0 );
	int isSelfsignedCert	( int idx = 0 );
	int verifyCertByKeypair	( int idx = 0 );
	int verifyCertByTrusties( int idx = 0 );
	int verifySelfsignedCert( int idx = 0 );
	
	int    getVerifyERRNumber	() 				{ return ctx_verifyCertErro; }
	string getVerifyERRString	() 				{ return X509_verify_cert_error_string( ctx_verifyCertErro ); }
	string getVerifyERRString	( int err_num )	{ return X509_verify_cert_error_string( err_num ); }

/*		// openssl errstr <hex value error from ERR_get_error()>
 * 
ERR_UNABLE_TO_GET_ISSUER_CERT
ERR_UNABLE_TO_GET_CRL
ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
ERR_CERT_SIGNATURE_FAILURE
ERR_CRL_SIGNATURE_FAILURE
ERR_CERT_NOT_YET_VALID
ERR_CERT_HAS_EXPIRED
ERR_CRL_NOT_YET_VALID
ERR_CRL_HAS_EXPIRED
ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
ERR_OUT_OF_MEM
ERR_DEPTH_ZERO_SELF_SIGNED_CERT
ERR_SELF_SIGNED_CERT_IN_CHAIN
ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
ERR_CERT_CHAIN_TOO_LONG
ERR_CERT_REVOKED
ERR_INVALID_CA
ERR_PATH_LENGTH_EXCEEDED
ERR_INVALID_PURPOSE
ERR_CERT_UNTRUSTED
ERR_CERT_REJECTED
ERR_SUBJECT_ISSUER_MISMATCH
ERR_AKID_SKID_MISMATCH
ERR_AKID_ISSUER_SERIAL_MISMATCH
ERR_KEYUSAGE_NO_CERTSIGN
ERR_INVALID_EXTENSION
ERR_INVALID_POLICY_EXTENSION
ERR_NO_EXPLICIT_POLICY
ERR_APPLICATION_VERIFICATION
*/
 
protected:

	int log_level;
	
	int ctx_verifyCertErro;

	X509_STORE *trustycerts;
	STACK_OF(X509_INFO) *trusties;

	X509* getStackItem( int idx = 0 ); //STACK_OF(X509_INFO) *&, int idx );

	EVP_PKEY 	*keypair;
	X509_REQ	*x509_req;
	
	STACK_OF(X509_INFO) *certstack;

	BIO* writeBIO( const char* fname = NULL );
	BIO*  readBIO( const char* );

	int readCertificate	( STACK_OF(X509_INFO) *&, const char* );
	int readKeypair		( EVP_PKEY*&, const char*, const char* PWD = NULL );
	// TODO: check the validity of the keypair, also how to sign a message using publick key;
	// http://stackoverflow.com/questions/29855538/programmatically-verify-a-x509-certificate-and-private-key-match
	int readCSR			( X509_REQ*&, const char* );

	static int verify_callback(int, X509_STORE_CTX *);
    static void print_san_name(const char*, X509* const);

    int verifyCertHostname( X509 *, char * );
	
	string to_hex_string( int ); // tlog->ERR( to_hex_string( ERR_get_error()));; To use openssl command to show the error string it takes the hex value

	string ssl_dir;
	
private:

	unique_ptr<ThreadLog> tlog;	
};

/* ************************************************************************************************ *
 *  OSSLCert Class
 * ************************************************************************************************ */
class OSSLCert : public OSSL
{
public:

	OSSLCert( int logLvl = LOG_ERR, const char* SSL_dir = "./ssl/" );
	~OSSLCert();
	
	int mkRSAF4Keypair	( int size = 2048 );
	int mkECCKeypair	( const char *type = "secp521r1" );
	
	// openssl ecparam -list_curves
	//
	// NID_X9_62_prime256v1
	// NID_secp224r1
	// secp521r1
	// sect571r1
	
	int initCACSR 			( const char* );
	int initServerCSR 		( const char* );
	int initClientCSR 		( const char* );
	
	int CSR_Country         ( const char* );
	int CSR_Province        ( const char* );
	int CSR_City            ( const char* );
	int CSR_Organization    ( const char* );
	int CSR_Email           ( const char* );
	
	int CSR_SAN             ( const char* );
	int CSR_SSLServer_Name  ( const char* );
	int CSR_Comment			( const char* );
	int CSR_CRL				( const char* );	// http://www.zedwood.com/article/cpp-check-crl-for-revocation
	int CSR_Custom_Ext      ( const char*, const char*, const char*, const char* );
	int mkCSR();
	
	int CRT2CSR();

	//http://stackoverflow.com/questions/16291809/programmatically-verify-certificate-chain-using-openssl-api
	int writePublicKey	( const char* fname = NULL );
	int writeKeypair	( const char* fname = NULL, const char* PWD = NULL );
	int writeCSR		( const char* fname = NULL );
	
	int readCRL			( const char* );
	int readDERCRL		( const char* );
	
	int certVersion					( int idx = 0 );
	int certSerial					( int idx = 0 );
	const string certSubject		( int idx = 0 );
	const string certIssuer			( int idx = 0 );
	unsigned long certSubjectHash	( int idx = 0 );
	
	const char* isCACert_str	( int idx = 0 );
	
	int certIssueTime	(  int idx = 0 );
	int certExpireTime	( int idx = 0 );
	
protected:

	int initCSR       			( const char* );
	int CSR_Cert_Type			( const char* );
	int CSR_KeyUsage			( const char* );
	int CSR_Basic_Constraints	( const char* );
	int CSR_ExtKeyUsage			( const char* );
	
	int CSR_addName( const char*, const char* );
	int CSR_addExtension( int, const char* );

	int verifyCACert( X509* );

	X509_STORE_CTX *ctx;
	
	X509_NAME	*x509_name;

	STACK_OF( X509_EXTENSION ) *extensions;

	X509_CRL	*x509_crl;
	STACK_OF( X509_REVOKED *) revokedstack;
	
	int Ver;
	
private:
	static int passwd_callback	( char*, int, int, void* );

	unique_ptr<ThreadLog> tlog;
};

/* ************************************************************************************************ *
 *  OSSLCA Class
 * ************************************************************************************************ */
class OSSLCA : public OSSLCert
{
public:
	OSSLCA( int logLvl = LOG_ERR, const char* SSL_dir = "./ssl/" );
	~OSSLCA();

	int initRootCACSR ( const char* );

	int mkCRL				( int dur = 7 ); // days

	int mkCert			( int dur = 365 );
	int mkSelfsignedCert( int dur = 365 );
	int appendCACert	();
	
	int verifyCertByCACert				( int idx = 0 );
	const string verifyCertByCACert_str	( int idx = 0 );
	
	int readCACert			( const char* );
	string readCABundle_str	( const char*, const char*, const char* CAPWD = NULL );
	int readCABundle		( const char*, const char*, const char* CAPWD = NULL );

	int writeCertificate	( const char* fname = NULL );
	int writeCRL			( const char* fname = NULL );
	int writeDERCRL			( const char* fname = NULL );
	
	int revokeCertificate	( uint64_t );
	int restoreRevoked		( uint64_t, time_t );
	
	int isExpired			();
	int cleanExpiredCerts	();
	
	EVP_PKEY* Keypair_dup	() { return keypair; }
	
protected:

	STACK_OF(X509_INFO) *CAsign_certs;
	EVP_PKEY* CAsign_EVPkey;

	uint64_t serialNumber;
	uint64_t    CRLNumber;
	
	int CRLVer;
	string CRLUri;

	int getSerialNumber	( uint64_t& );
	int getCRLNumber	( uint64_t& );
	int getCRLUri		(   string& );

	int isExpired		( const char* );
	
	int addRevokedCert	( uint64_t, time_t );
	
private:

	unique_ptr<ThreadLog> tlog;
};

#endif

/* ******************************************************************************************* * /

    //openssl genrsa -out private/private.key 2048
	openssl genrsa -des3 -aes256 -out rsa_private.key 2048

    openssl req -config ../openssl.cnf -key private/rsa_private.key -new -sha256 -out pumchal.csr

	openssl req -in pumchal.csr -text -noout | more
	
	# NOTE: CName should match your hostname or 'IP address' (ie: 127.0.0.1, or pumchal.com) which 
	# client will type in the browser address bar.

    cd ../IA/
    openssl ca -config ../openssl.cnf -policy default_policy -days 365 \
    -notext -md sha256 -in ../pumchal.com/pumchal.csr -out ../pumchal.com/pumchal.pem

    cd -
    ln -sf pumchal.pem pumchal.crt

	# remove the private key's password
	openssl rsa -in private/rsa_private.key -out private/private.key
	
	# if server app, as usual, accepts the privatekey and certificate on the same file:
    cat private/private.key pumchal.pem > hold.pem
    mv hold.pem pumchal.pem

	#---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---
    # Optionally convert X.509 cert. to PKCS#12 for client application like Browser or Email client
    openssl pkcs12 -export -in pumchal.pem -out pumchal.pfx -name "Certificate for Pumchal.com"
	#---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---

    openssl x509 -in pumchal.pem -text -noout | more

	# to verify certificate against signer (IA) certificate:
    openssl verify -CAfile ../IA/public/iachain.crt pumchal.pem

	#---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---
	# the above command works only for pem format. If you has .p12 file, then first convert it to pem format:
    openssl pkcs12 -nodes -in pumchal.pfx -out temp.crt
	#---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---
	
	# You would install the .key, the signed .crt and ../IA/iachain.cert.pem files on the target server


/* ******************************************************************************************* */
