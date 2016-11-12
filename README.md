BitcoinWallet
=============

BitcoinWallet is a Simple Payment Verification (SPV) Bitcoin wallet written in Java.  It allows you to send and receive coins using Pay-To-Pubkey-Hash payments.  It has a 'wallet' and a 'safe'.  The safe contains coins that are not to be spent until they are moved to the wallet.  It uses a single change address because I'm not worried about being anonymous on the network and don't want to take a chance on losing coins because I forgot to back up the wallet after making a transaction.  

BitcoinWallet supports two address format.  A P2PKH address starts with '1' while a P2SH address starts with '3'.  BitcoinWallet supports just a P2SH-P2WPKH acript when using a P2SH address.  Refer to BIP 143 for more information on witness scripts.

Bloom filters are used to reduce the amount of data sent to the wallet from the peer nodes.  This means that BitcoinWallet will only connect to nodes that support bloom filters (NODE_BLOOM is set in the node services).

A segregated witness transaction is created if a P2SH-P2WSH output is spent or coins are sent to a P2SH-P2WSH address.  Otherwse, a non-segregated witness transaction is created.  This means that BitcoinWallet will only connect to nodes that support segregated witness (NODE_WITNESS is set in the node services) since transaction verification will fail if a segregated witness transaction is sent to a node that doesn't support segregated witness.

You can use the production network (PROD) or the regression test network (TEST).  The regression test network is useful because bitcoind will immediately generate a specified number of blocks.  To use the regression test network, start bitcoind with the -regtest option.  You can then generate blocks using bitcoin-cli to issue 'setgenerate true n' where 'n' is the number of blocks to generate.  Block generation will stop after the requested number of blocks have been generated.  Note that the genesis block, address formats and magic numbers are different between the two networks.  BitcoinWallet will create files related to the TEST network in the TestNet subdirectory of the application data directory.

H2 is used for the wallet database and the files will be stored in the Database subdirectory of the application data directory.

BouncyCastle is used for the elliptic curve functions.  Version 1.51 provides a custom SecP256K1 curve which significantly improves ECDSA performance.  Earlier versions of BouncyCastle do not provide this support and will not work with BitcoinWallet.

Simple Logging Facade is used for console and file logging.  I'm using the JDK logger implementation which is controlled by the logging.properties file located in the application data directory.  If no logging.properties file is found, the system logging.properties file will be used (which defaults to logging to the console only).


Build
=====

I use the Netbeans IDE but any build environment with Maven and the Java compiler available should work.  The documentation is generated from the source code using javadoc.

Here are the steps for a manual build.  You will need to install Maven 3 and Java SE Development Kit 8 if you don't already have them.

  - Build and install BitcoinCore (https://github.com/ScripterRon/BitcoinCore)      
  - Create the executable: mvn clean package
  - [Optional] Create the documentation: mvn javadoc:javadoc
  - [Optional] Copy target/BitcoinWallet-v.r.jar and target/lib/* to wherever you want to store the executables.
  - Create a shortcut to start BitcoinWallet using java.exe for a command window or javaw.exe for GUI only. 


Runtime Options
===============

The following command-line arguments are supported:
	
  - PROD	
    Start the program using the production network. Application files are stored in the application data directory and the production database is used. DNS discovery will be used to locate peer nodes if no peers are specified in BitcoinWallet.conf.
	
  - TEST	
    Start the program using the regression test network. Application files are stored in the TestNet folder in the application data directory and the test database is used. At least one peer node must be specified in BitcoinWallet.conf since DNS discovery is not supported for the regression test network.

The following command-line options can be specified using -Dname=value

  - bitcoin.datadir=directory-path		
    Specifies the application data directory. Application data will be stored in a system-specific directory if this option is omitted:		
	    - Linux: user-home/.BitcoinWallet	
		- Mac: user-home/Library/Application Support/BitcoinWallet	
		- Windows: user-home\AppData\Roaming\BitcoinWallet	
	
  - java.util.logging.config.file=file-path		
    Specifies the logger configuration file. The logger properties will be read from 'logging.properties' in the application data directory. If this file is not found, the 'java.util.logging.config.file' system property will be used to locate the logger configuration file. If this property is not defined, the logger properties will be obtained from jre/lib/logging.properties.
	
    JDK FINE corresponds to the SLF4J DEBUG level	
	JDK INFO corresponds to the SLF4J INFO level	
	JDK WARNING corresponds to the SLF4J WARN level		
	JDK SEVERE corresponds to the SLF4J ERROR level		

The following configuration options can be specified in BitcoinWallet.conf.  This file is optional and must be in the application directory in order to be used.	

  - connect=[address]:port		
	Specifies the address and port of a peer node.  This statement can be repeated to define multiple nodes.  If this option is specified, connections will be created to only the listed addresses and DNS discovery will not be used.     
	
Sample Windows shortcut:	

	javaw.exe -Xmx256m -jar \Bitcoin\BitcoinWallet\BitcoinWallet-3.0.1.jar PROD
