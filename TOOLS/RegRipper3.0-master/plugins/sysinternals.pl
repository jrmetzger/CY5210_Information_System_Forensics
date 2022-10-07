#-----------------------------------------------------------
# sysinternals.pl
#  
#
# Change history
#   20200511 - updated date output format
#   20120608 - created
#
# References
#
# 
# copyright 2020 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package sysinternals;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080324);

sub getConfig{return %config}
sub getShortDescr {
	return "Checks for SysInternals apps keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching sysinternals v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\SysInternals';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("SysInternals");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".::getDateFromEpoch($key->get_timestamp())."Z");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) { 
				::rptMsg($s->get_name()." [".::getDateFromEpoch($s->get_timestamp())."Z]");
				
				my $eula;
				eval {
					$eula = $s->get_value("EulaAccepted")->get_data();
				};
				if ($@) {
					::rptMsg("  EulaAccepted value not found.");
				}
				else {
					::rptMsg("  EulaAccepted: ".$eula);
				}
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;