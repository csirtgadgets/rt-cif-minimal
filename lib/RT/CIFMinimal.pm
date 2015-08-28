package RT::CIFMinimal;

use warnings;
use strict;

our $VERSION = '2.0';
$VERSION = eval $VERSION;  # see L<perlmodstyle>

# a work-around for now
use lib '/opt/cif/lib/perl5';

use Net::Abuse::Utils qw(:all);
use Regexp::Common qw/net URI/;
use Net::CIDR;
use CIF::SDK::Client qw/parse_config/;
use RT::CIF_Hash;
use CIF::StorageFactory;
use CIF::SDK::FormatFactory;
use Try::Tiny;

my $storage = CIF::StorageFactory->new_plugin({ 
    plugin => 'elasticsearch'
});

my @ipv4_private = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "224.0.0.0/4",
    "240.0.0.0/5",
    "248.0.0.0/5"
);

sub IsPrivateAddress {
    my $addr = shift;
    my ($found,$err);
    try {
        $found =  Net::CIDR::cidrlookup($addr,@ipv4_private);
    } catch {
        $err = shift;
        $found = 0;
    }
    return($found);
}

sub cif_submit {
    my $args = shift;
    
    my $report  = $args->{'report'};
    my $guid    = $args->{'group'} || 'everyone';

    my ($err,$ret) = CIF::SDK::Client->new({
        config  => RT->Config->Get('CIFMinimal_CifConfig') || '/home/cif/.cif.yml',
    });
    my $cli = $ret;
    $ret = $cli->new_submission({
        guid    => $guid,
        data    => $report->encode(),
    });

    return $cli->submit($ret);
}

sub cif_data {
    my $args = shift;
    
    my $fields  = $args->{'fields'} || 'tlp,group,confidence,observable,rdata,portlist,protocol,tags,description,reporttime';
    my $q       = $args->{'q'}      || $args->{'query'};
    my $nolog   = $args->{'nolog'}  || 0;
    my $limit   = $args->{'limit'}  || 25;
    my $results = $args->{'results'};
    my $user    = $args->{'user'};
    
    return unless($q);
    my ($ret,$err);
    my $token = user_list($user);
    
    my $client = CIF::SDK::Client->new({
        remote  => 'https://localhost', # TODO
        verify_ssl => 0,
    });
    
    unless($token){
        # generate apikey
        $token = generate_apikey({ user => $user, description => 'generated automatically via RT' });
        unless($token){
            push(@$results, 'unable to automatically generate an apikey, please contact your administrator');
            $RT::Logger->error('unable to generate an apikey for: '.$user->EmailAddress());
            return;
        } else {
            $client->{'token'} = $token;
            push(@$results,'default WebUI apikey '.$token.' automatically generated');
        }
    } else {
        $client->{'token'} = @{$token}[0]->{'token'};
    }

    my @res;
    my @array = split(/,/,$q);
    
    warn $q;
    
    ($ret, $err) = $client->search({
        observable  => $q,
        nolog       => 0,
        limit       => $limit,
    });

    my @html;
    unless($ret){
        push(@$results,'no results...');
        return;
    } else {
        push(@html, @$ret);
    }
    
    my $formatter = CIF::SDK::FormatFactory->new_plugin({ 
        format => 'html', 
    });
    my $text = $formatter->process(\@html);

    return($text);
}

sub user_list {
    my $user = shift;
    
    return unless($user && ref($user) eq 'RT::User');

    my $rv = $storage->token_list({ Username => $user->EmailAddress() });
    return $rv;
}
    

sub remove_key {
    my $key = shift;
    return unless($key);

    my $rv = $storage->token_delete({
        Token       => $key,
    });
    return $rv;
}

sub generate_apikey {
    my $args            = shift;
    my $user            = $args->{'user'};
    my $key_desc        = $args->{'description'};
    my $add_groups      = $args->{'groups'};
    my $restrictions    = $args->{'restrictions'};

    return unless($user && ref($user) eq 'RT::User');
    

    my @a_groups = (ref($add_groups) eq 'ARRAY') ? @$add_groups : $add_groups;

    my $g = $user->OwnGroups();
    my %group_map;

    while(my $grp = $g->Next()){
        next unless($grp->Name() =~ /^DutyTeam (\S+)/);
        my $guid = lc($1);
        my $priority = $grp->FirstCustomFieldValue('CIFGroupPriority') || 0;
        $group_map{$guid} = $priority;
    }
    $group_map{'everyone'} = 1000;
    my @sorted = sort { $group_map{$a} cmp $group_map{$b} } keys(%group_map);

    unless($a_groups[0]){
        @a_groups = @sorted;
    } else {
        foreach (@a_groups){
            return unless(exists($group_map{$_}));
        }
    }

    my $rv = $storage->token_new({
        Username        => $user->EmailAddress() || $user->Name(),
        'read'          => 1,
        description     => $key_desc,
        groups          => \@a_groups,
    });
    return $rv;
}

sub network_info {
    my $addr = shift;

    return if(IsPrivateAddress($addr));
    my ($as,$network,$ccode,$rir,$date) = get_asn_info($addr);
    my $as_desc = '';
    if($as){
        $as_desc = get_as_description($as);
    }
    return({
        asn         => $as,
        cidr        => $network,
        cc          => $ccode,
        rir         => $rir,
        modified    => $date,
        description => $as_desc,
    }) if($as);
    return(0);
}

sub ReportsByType {
    my $user    = shift;
    my $group   = shift;
    my $limit   = shift;
    
    return if($limit && $limit !~ /^\d+$/);
    return if($group && $group !~ /^[a-zA-Z0-9.\-_]+\.[a-z]{2,6}$/);

    my @called = caller();
    my $type = $called[1];
    my @t = split(/\//,$type);
    $type = $t[$#t];
    my $category = $t[$#t-1];

    my $reports = RT::Tickets->new($user);
    my $query = "Queue = 'Incident Reports' AND (Status = 'new' OR Status = 'open') AND 'CF.{confidence}' IS NOT NULL AND 'CF.{tags}' IS NOT NULL AND 'CF.{observable}' IS NOT NULL";
    if($group){
        $query .= " AND 'CF.{Constituency}' = '".lc($group)."'";
    }
    if($limit){
       $reports->RowsPerPage($limit);
    }

    $reports->FromSQL($query);
    $reports->OrderByCols({FIELD => 'id', ORDER => 'DESC'});

    my $array;
    my $x = 0;
    while(my $r = $reports->Next()){
        push(@$array,$r->cif_hash());
    }
    return [] unless($#{$array} > -1);
    return($array);
}

{
    my %cache;
    sub GetCustomField {
        my $field = shift or return;
        return $cache{ $field } if exists $cache{ $field };

        my $cf = RT::CustomField->new( $RT::SystemUser );
        $cf->Load( $field );
        return $cache{ $field } = $cf;
    }
}

eval "require RT::CIFMinimal_Vendor";
die $@ if ($@ && $@ !~ qr{^Can't locate RT/CIFMinimal_Vendor.pm});
eval "require RT::CIFMinimal_Local";
die $@ if ($@ && $@ !~ qr{^Can't locate RT/CIFMinimal_Local.pm});

package RT::User;
use Hook::LexWrap;
{
my $obj;
wrap 'RT::User::Create',
    pre => sub {
        my $user = $obj = $_[0];
        my %args = (@_[1..(@_-2)]);
        return if($args{'EmailAddress'});
        unless($args{'EmailAddress'}){ $args{'EmailAddress'} = $args{'Name'}; }
        my @res = $user->Create(%args);
        $_[-1] = \@res;
    },
    post => sub {
        return unless $_[-1];
        my $val = ref $_[-1]? \$_[-1][0]: \$_[-1];
        return unless($val =~ /\d+/);

        if(my %map = RT->Config->Get('CIFMinimal_UserGroupMapping')){
            my $x = $ENV{$map{'EnvVar'}};
            my @tags = split($map{'Pattern'},$x);
            my $group_map = $map{'Mapping'};
            foreach(keys %$group_map){
                foreach my $g (@tags){
                    if($g eq $_){
                        require RT::Group;
                        my $y = RT::Group->new($RT::SystemUser);
                        my ($ret,$err) = $y->LoadUserDefinedGroup($group_map->{$_});
                        $RT::Logger->debug("adding user to group: $g");  
                        ($ret,$err) = $y->AddMember($$val);
                        unless($ret){
                            $RT::Logger->error("Couldn't add user to group: ".$y->Name());
                            $RT::Logger->error($err);
                            $RT::Handle->Rollback();
                            return(0);
                        }
                    }
                }
            }
        } elsif (my $default = RT->Config->Get('CIFMinimal_DefaultUserGroup')){
            require RT::Group;
            my $default = RT->Config->Get('CIFMinimal_DefaultUserGroup');
            return unless($default);
            my $group = RT::Group->new($obj->CurrentUser());
            my ($ret,$err) = $group->LoadUserDefinedGroup($default);
            unless($ret){
                $RT::Logger->error("Couldn't add user to group: ".$default.': '.$err);
                return(0);
            }
            ($ret,$err) = $group->_AddMember(InsideTransaction => 1, PrincipalId => $$val);
            unless($ret){
                $RT::Logger->error("Couldn't add user to group: ".$group->Name());
                $RT::logger->error($err);
                $RT::Handle->Rollback();
                return(0);
            }
        }
    }
}
1;
