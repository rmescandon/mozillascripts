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

### output folder to leave pem files
my $output_folder = './CAs';

### extension for certificates get from mozilla and stored in individual files
my $certs_extension = '.pem';

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
unless(-d $output_folder){
    mkdir $output_folder or die "$output_folder output folder to leave created certficate pem files could not be created";
    print "created $output_folder output folder\n";
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

	###setting as file name for this certificate the CA name
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
print "\n\nDone ($certnum CA certs processed, $skipnum untrusted skipped).\n";
print "PEM certificates for CAs have been generated in $output_folder folder. Process finished sucessfully!!\n";

exit;


