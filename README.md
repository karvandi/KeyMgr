
The KeyMgr is an example program on how to use some of openssl functions to
generate certificates and keypairs. The OSSL* wrapper classes in the Secure.cpp
are the interface to the openssl library.

The code compiled by GNU compiler (g++) on the Ubuntu 16.04. This software is 
provided 'as-is', without any express or implied warranty.  In no event will 
the authors be held liable for any damages as result of the use of this software.

Babak Karvandi - 12 April 2017
bkarvandi@yahoo.com

Additional Information:
-----------------------

To compile the code make sure the openssl package is installed and simnply 
enter "./make" command. Ther after run the "./KeyMgr -h" to get the help
screen with list of command line switches.

the default certificate/database directory is "./ssl/" which can be changed 
by passing the -f switch on command line.




# KeyMgr
