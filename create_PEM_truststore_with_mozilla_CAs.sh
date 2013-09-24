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

### truststore name
my $truststore = $ARGV[1] || 'truststore.pem';
#########################
### END VAR DEFININITIONS
#########################



### 
###set locale
$ENV{'LANG'} = 'en_US.UTF-8';

##########
### Prepare environment
###########
### delete certdata.txt if exists
(my $txt = $url) =~ s@(.*/|\?.*)@@g;
if (-e $txt){
   system("rm -f $txt");
   print "deleted previous $txt file\n";
}


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

	###write certificate content in truststore file
	open(TRUSTSTORE, ">>$truststore") or die "Couldn't open $truststore: $!";
	print TRUSTSTORE $pem;
	close(TRUSTSTORE) or die "Couldn't close $truststore: $!";
	print "Parsing: $caname\n";
	$certnum ++;
	$start_of_cert = 0;
      ##RME 266 END
    }
  }
}
close(TXT) or die "Couldn't close $txt: $!";
print "Done ($certnum CA certs processed, $skipnum untrusted skipped).\n";





print "\n\n". $truststore . " keystore population with mozilla CAs was finished sucessfully!!\n";

exit;


