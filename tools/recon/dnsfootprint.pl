#!/usr/bin/perl

use strict;

#dns stuff
use NetAddr::IP;
use Net::DNS;
use Net::IP;
use Net::XWhois;

use Getopt::Long;
use Data::Dumper;

my %opts;

GetOptions(\%opts, "n=s", "d=s", "a=s") || die "$!\n";

unless ($opts{'n'} || $opts{'d'} || $opts{'a'})
{
  die &usage;
}

my @domains;
my @ips;

if($opts{'d'})
{
  open(DOMAINS, "<$opts{d}") || die "could not open $opts{d} for reading: $!\n";
  while(<DOMAINS>)
  {
    my $d = $_;
    chomp $d;
    push(@domains, $d);
  }
  close(DOMAINS);
}
if($opts{'n'})
{
  push(@domains, $opts{'n'});
}
if($opts{'a'})
{
  open(IPS, "<$opts{a}") || die "could not open $opts{a} for reading: $!\n";
  while(<IPS>)
  {
    my $i = $_;
    chomp $i;
    my @iplist = expandIP($i);
    foreach my $ip (@iplist)
    {
      push(@ips, $ip);
    }
  }
}

my @host_prefixes = (
       'www', 'www1', 'www2', 'www3', 'ns', 'ns1', 'ns2', 'ns3',
       'webmail', 'mail', 'mail1', 'mail2', 'mail3', 'mx', 'mx1',
       'mx2', 'mx3', 'web400', 'ls', 'firewall', 'fw', 'webmin', 
       'internal', 'wiki', 'external', 'intranet', 'blog', 'secure',
       'ftp', 'dns', 'dns1', 'dns2', 'dns3', 'web', 'feed', 'rss',  
       'nfs', 'files', 'file', 'fileserver', 'dmz', 'hr', 'sales',  
       'records', 'marketing', 'sonicwall', 'pix', 'asa', 'border', 
       'gw', 'pop', 'pop3', 'imap', 'smtp', 'dhcp', 'remote', 'vpn',
       'citrix', 'ts', 'terminalservice', 'rdp', 'test', 'www-test',
       'wwwtest', 'ids', 'snort', 'dev', 'development', 'termserve',
       'admin', 'webmin', 'gateway', 'cisco', 'secure');
                                                                                        

my $resolver = Net::DNS::Resolver->new();

foreach my $domain (@domains)
{
  print "Processing domain $domain...\n";
  
  #open(OUT, ">footprinting-$domain.txt") || die "Could not open footprinting-$domain.txt for writing: $!\n";
  
  #Pull whois info
  print "[*]Querying whois information for domain...\n";
  my $whois = new Net::XWhois Domain => $domain ;
  #print Dumper($whois);
  #print "name: ",$whois->name(),"\n";
  #print "status: ",$whois->status(),"\n";
  #print "registrant: ",$whois->registrant,"\n";
  print $whois->response();
  print OUT "**********************************\n";
  print OUT "*  Whois information             *\n";
  print OUT "**********************************\n";
  print OUT $whois->response(),"\n";

  #Query for nameservers for the domain
  print "[*]Querying name servers for domain...\n";
  print OUT "**********************************\n";
  print OUT "*  Name servers                  *\n";
  print OUT "**********************************\n";
  my @nameservers;
  my $ns_req = $resolver->query($domain, "NS");
  if(!(defined($ns_req) && ($ns_req->header->ancount > 0)))
  {
    warn "[!]No nameservers found for $domain ", $resolver->errorstring, "\n";
    print OUT "No name serverse found ", $resolver->errorstring, "\n";
  }
  else
  {
    #print Dumper($ns_req);
    foreach my $ans ($ns_req->answer)
    {
#     print Dumper($ans);
      print $ans->nsdname, "\n";
      print OUT $ans->nsdname, "\n";
      push(@nameservers, $ans->nsdname);
    }

    #Query for MX records
    print "[*]Querying for MX records...\n";
    print "[*]Querying name servers for domain...\n";
    print OUT "**********************************\n";
    print OUT "*  Mail servers                  *\n";
    print OUT "**********************************\n";

    my $mx_req = $resolver->query($domain, "MX");
    if(!(defined($mx_req) && ($mx_req->header->ancount > 0)))
    {
      warn "[!]No MX records found for $opts{d}: ", $resolver->errorstring, "\n";
      print OUT "No MX records found ", $resolver->errorstring, "\n";
    }
    else
    {
#      print Dumper($mx_req);
      foreach my $ans ($mx_req->answer)
      {
#       print Dumper($ans);
        print $ans->exchange . "\t" . $ans->preference . "\n";
        print OUT $ans->exchange . "\t" . $ans->preference . "\n";
      }
    }
    print "[*]Checking SPF records...\n";
    print OUT "*********************************\n";
    print OUT "*  SPF record                   *\n";
    print OUT "*********************************\n";
    my $spf_req = $resolver->query($domain, "TXT");
    if($spf_req)
    {
      foreach my $rr ($spf_req->answer)
      {
        next unless $rr->txtdata =~ m/v=spf/;
        print "SPF record: ",$rr->txtdata, "\n";
        print OUT $rr->txtdata, "\n";
      }
    }
    else
    {
      warn "[!] No SPF record found\n";
      print OUT "No SPF record found\n";
    }

    print "[*]Bruteforcing host names...\n";
    print OUT "**********************************\n";
    print OUT "*  Bruteforced names             *\n";
    print OUT "**********************************\n";
    {
    my $name_query = $resolver->query($domain, "A");
      #print Dumper($name_query);
      if($name_query)
      {
        print "  [+]Resolved $domain to:\n";
        foreach my $ans($name_query->answer)
        {
#         print Dumper($ans);
          if($ans->type eq 'CNAME')
          {
            print "    ",$ans->cname,"\t",$ans->type,"\n";
            print OUT "$domain\t",$ans->cname,"\t",$ans->type,"\n";
#           print Dumper($ans);
          }
          else
          {
            print "    ",$ans->name,"\t",$ans->address,"\t",$ans->type,"\n";
            print OUT "$domain\t",$ans->name,"\t",$ans->address,"\t",$ans->type,"\n";
          }
        }
      }
      foreach my $prefix (@host_prefixes)
      {
        my $name = "$prefix.$domain";
        my $name_query = $resolver->query($name, "A");
        #print Dumper($name_query);
        if($name_query)
        {
          print "  [+]Resolved $name to:\n";
          foreach my $ans($name_query->answer)
          {
#            print Dumper($ans);
            if($ans->type eq 'CNAME')
            {
              print "    ",$ans->cname,"\t",$ans->type,"\n";
              print OUT "$name\t",$ans->cname,"\t",$ans->type,"\n";
#              print Dumper($ans);
            }
            else
            {
              print "    ",$ans->name,"\t",$ans->address,"\t",$ans->type,"\n";
              print OUT "$name\t",$ans->name,"\t",$ans->address,"\t",$ans->type,"\n";
            }
          }
        }
      }
    }


    print "[*]Attempting zone transfer on all name servers...\n";
    print OUT "**********************************\n";
    print OUT "*  Zone transfer                 *\n";
    print OUT "**********************************\n";

    {
      foreach my $ns (@nameservers)
      {
        my $axfr_res = Net::DNS::Resolver->new;
        $axfr_res->nameservers($ns);
        my @rrs = $axfr_res->axfr($ns);
        if(@rrs)
        {
          print "[+]Zone transfer succeeded using $ns\n";
          foreach my $rr(@rrs)
          {
            $rr->print;
            print out $rr->print;
          }
        }
        else
        {
          print "[-]Zone transfer of $domain failed using $ns, this is probably a good thing: ", $axfr_res->errorstring, "\n";
          print OUT "Zone tranfer failed using $ns: ", $axfr_res->errorstring, "\n";
#          print Dumper($axfr_res);
        }
      }
    }
  }
  close(OUT);
}
#open(OUTW, ">footprinting-ip-whois.txt") || die "could not open footprinting-ip-whois.txt for writing: $!\n";
#open(OUTR, ">footprinting-ip-rdns.txt") || die "could not open footprinting-ip-rdns.txt for writing: $!\n";
for my $ip (@ips)
{
  print "Processing IP Address: $ip\n";
  print "[*]Querying whois information for $ip...\n";
  print OUTW "$ip\n";
  my $whois = new Net::XWhois Domain => $ip;
  print $whois->response();
  print OUTW $whois->response();
  print "[*]Resolving Reverse DNS for $ip...\n";
  my $ipo = new Net::IP($ip);
  my $rdns_query = $resolver->query($ipo->reverse_ip(), "PTR");
  if($rdns_query)
  {
    foreach my $ans ($rdns_query->answer)
    {
      print "  resolves to ". $ans->ptrdname."\n";
      print OUTR "$ip resovles to ". $ans->ptrdname."\n";
    }
  }
  else
  {
    print "  no rdns record\n";
    print OUTR "$ip does not have a rdns record\n";
  }

}
close(OUTW);
close(OUTR);


sub expandIP
{
  my ($range) = @_;
  my @addresses;
  if($range =~ m/-/)
  {
    my @octets = split ( /\./, $range);
    my (@range0, @range1, @range2, @range3);
    my ($ctr0, $ctr1, $ctr2, $ctr3);
    
    @range0 = split(/\-/, $octets[0]);
    $ctr0 = $range0[0];
    while($ctr0 <= $range0[@range0-1])
    {
      @range1 = split(/\-/, $octets[1]);
      $ctr1 = $range1[0];
      while ($ctr1 <= $range1[@range1-1])
      {
        @range2 = split(/\-/, $octets[2]);
        $ctr2 = $range2[0];
        while($ctr2 <= $range2[@range2-1])
        {
          @range3 = split(/\-/, $octets[3]);
          $ctr3 = $range3[0];
          while($ctr3 <= $range3[@range3-1])
          {
            push(@addresses, "$ctr0.$ctr1.$ctr2.$ctr3");
            $ctr3++;
          }
          $ctr2++;
        }
        $ctr1++;
      }
      $ctr0++;
    }                                      
  }
  elsif($range =~ m/\//)
  {
    my $n = NetAddr::IP->new( $range );
    for my $ip( @{$n->hostenumref} ) 
    {
      push(@addresses, $ip->addr);
    }
  }
  else
  {
    push(@addresses, $range);
  }
  return @addresses;
}

sub usage
{
  die <<EOF;
USAGE: $0 -n <domain name> -d <domain name list file> -a <ip address file>\n 
EOF
}
