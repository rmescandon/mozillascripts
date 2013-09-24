#!/usr/bin/perl -w
# ***************************************************************************
#


use Getopt::Std;
use MIME::Base64;
use LWP::UserAgent;
use strict;

###################
### VAR DEFINITIONS
###################
### If the OpenSSL commandline is not in search path you can configure it here!
my $openssl = 'openssl';

### User agent version to connect to remote url for downloading certdata
my $version = '1.16';

### url where mozilla raw certdata file is
my $url = $ARGV[0] || 'http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1';

### output temporal folder to deploy pem files
my $output_folder = '/tmp/output';

### extension for certificates get from mozilla and stored in individual files
my $certs_extension = '.pem';

### truststore name
my $truststore = $ARGV[1] || 'truststore.jks';

### truststore password
my $truststore_password = 'truststore';
#########################
### END VAR DEFININITIONS
#########################



### 
###set locale
$ENV{'LANG'} = 'en_US.UTF-8';

##########
### Prepare environment
###########
### create output folder if not exists
my $must_be_deleted_output_folder = 0;
unless(-d $output_folder){
    mkdir $output_folder or die "$output_folder output temporal folder to leave created certficate pem files could not be created";
    print "created $output_folder temp folder\n";
    $must_be_deleted_output_folder = 1;
}
### delete certdata.txt if exists
(my $txt = $url) =~ s@(.*/|\?.*)@@g;
if (-e $txt){
   system("rm -f $txt");
   print "deleted previous $txt file\n";
}



my $crt = '';
my $resp;
## download certfile.txt
print "Downloading '$txt' ... please, wait\n";
my $ua  = new LWP::UserAgent(agent => "$0/$version");
$ua->env_proxy();
$resp = $ua->mirror($url, $txt);


print "Processing  '$txt' ...\n";
my $caname;
my $certnum = 0;
my $skipnum = 0;
my $start_of_cert = 0;

####### process downloaded certdata to create a 'plain' truststore with all certificates in base64
open(TXT,"$txt") or die "Couldn't open $txt: $!";
while (<TXT>) {
  
 
  # this is a match for the start of a certificate
  if (/^CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE/) {
    $start_of_cert = 1
  }
  if ($start_of_cert && /^CKA_LABEL UTF8 \"(.*)\"/) {
    $caname = $1;
  }
  my $untrusted = 0;
  if ($start_of_cert && /^CKA_VALUE MULTILINE_OCTAL/) {
    my $data;
    while (<TXT>) {
      last if (/^END/);
      chomp;
      my @octets = split(/\\/);
      shift @octets;
      for (@octets) {
        $data .= chr(oct);
      }
    }
    # scan forwards until the trust part
    while (<TXT>) {
      last if (/^CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST/);
      chomp;
    }
    # now scan the trust part for untrusted certs
    while (<TXT>) {
      last if (/^#/);
      if (/^CKA_TRUST_SERVER_AUTH\s+CK_TRUST\s+CKT_NSS_NOT_TRUSTED$/
          or /^CKA_TRUST_SERVER_AUTH\s+CK_TRUST\s+CKT_NSS_TRUST_UNKNOWN$/) {
          $untrusted = 1;
      }
    }
    if ($untrusted) {
      $skipnum ++;
    } else {
      my $pem = "-----BEGIN CERTIFICATE-----\n"
              . MIME::Base64::encode($data)
              . "-----END CERTIFICATE-----\n";
     
      ##RME 266 INIT

	###assing as file name for this certificate the CA name
	my $filename = $caname;
	###format filename avoiding blank or / 
	$filename =~ s/\s//g;
	$filename =~ s/\///g;
	

	###compose absolute path to pem file
	my $crt=$output_folder."/".$filename.$certs_extension;

	###delete previous file if exists
	if (-e $crt){
	   system("rm -f $crt");
	}
	
	###write certificate content in a new file
	open(CRT, ">>$crt") or die "Couldn't open $crt: $!";
	print CRT $pem;
	close(CRT) or die "Couldn't close $crt: $!";
	print "Parsing: $caname\n";
	$certnum ++;
	$start_of_cert = 0;
      ##RME 266 END
    }
  }
}
close(TXT) or die "Couldn't close $txt: $!";
print "Done ($certnum CA certs processed, $skipnum untrusted skipped).\n";



#################################################################################
#Second part.. process all .pem certificates and include them into jks truststore
#################################################################################

###
### first of all, create an empty truststore.jks
###

### created and filled temp file with standard input values for foo alias in truststore
### This alias will be deleted next. Is the way of creating an empty jks keystore
system("echo nombre >> tmp.file");
system("echo neosdp >> tmp.file");
system("echo TID >> tmp.file");
system("echo city >> tmp.file");
system("echo state >> tmp.file");
system("echo ES >> tmp.file");
system("echo yes >> tmp.file");
system("keytool -genkey -alias foo -keystore $truststore -storepass $truststore_password < tmp.file");
system("rm -f tmp.file");
system("keytool -delete -alias foo -keystore $truststore -storepass $truststore_password");

### check truststore has been created
unless (-e $truststore){
   print "\n" . $truststore . " could not be created\n";
   exit 1; 
}

###
### for every .pem file into output directory, import it as trust ca int truststore
### read all files in output folder (pem files) for iterate over them
my @files = <$output_folder/*>; 
my $filename='';

###added yes response to tmp file for asking if we want to add certificate to truststore for every import operation 
system("echo yes >> tmp.file");
foreach my $file (@files) {
        ### get the filename without folder or extension to be used as alias for certificate into truststore
        $filename = $file;
        $filename =~ s/$output_folder//g;
        $filename =~ s/$certs_extension//g;
        print "importing..." . $filename . "\n";
        ### import certificate in truststore
        system("keytool -import -trustcacerts -alias $filename -file $file -keystore $truststore -storepass $truststore_password < tmp.file");
}
### delete temp files and output folder
system("rm -f tmp.file");
if ($must_be_deleted_output_folder == 1){
	system("rm -rf $output_folder");
}


print "\n\n". $truststore . " keystore population with mozilla CAs was finished sucessfully!!\n";

exit;


