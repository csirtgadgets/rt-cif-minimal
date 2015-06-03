package RT::Ticket;

# this is used to generate the feed...
sub cif_hash {
	my $self = shift;
	my $args = shift;

    my $tkt = $self;

	my $cfs = RT::CustomFields->new($self->CurrentUser());
	$cfs->LimitToQueue($tkt->Queue());
	$cfs->Limit(FIELD => 'Description', VALUE => '_IODEF_Incident', OPERATOR => 'LIKE');
	return(undef) unless($cfs->Count());
	
	# we're doing this to avoid all the lookups with FirstCustomFieldValue
	# performance issue when we try to load lots of tickets
	my $mapped_cf = {};
	foreach(@{$cfs->ItemsArrayRef()}){
	    $mapped_cf->{$_->Id()} = { Name =>  $_->Name() };
	}
    my $local_values = {};
    
    foreach my $x (@{$tkt->CustomFieldValues->ItemsArrayRef()}){
        # map custom field to values array
        my $name = $mapped_cf->{$x->CustomField()}->{'Name'};
        # no name means it's disabled.
        next unless($name);
        #$local_values->{$name} = $x->Content();
        push(@{$local_values->{$name}},$x->Content());
    }

    my $source = $tkt->OwnerObj->EmailAddress() || $tkt->RequestorAddresses || RT->Config->Get('Organization');
    if($source =~ /,/){
        my @a = split(/,/,$source);
        $source = $a[0];
    }

    my $altid = RT->Config->Get('WebURL').'Ticket/Display.html?id='.$tkt->Id();
    my $altid_restriction = 'red';
    my $detecttime = $self->CreatedObj->AsString();

    # we do firstcustom.. here because it won't show up in our _IODEF_ CF search
    my $group = $tkt->FirstCustomFieldValue('Constituency') || $tkt->FirstCustomFieldValue('_RTIR_Constituency');

    my $restriction = $local_values->{'Restriction'}[0] || 'red';
    $restriction = 'red' unless($restriction =~ /^(default|private|need-to-know|public)$/);
    my $alt_restriction = 'red';
    $alt_restriction = 'green' if($alt_restriction eq 'white');

    my $report = {
        group       => $group,
        provider    => $source,
        tlp         => $restriction,
        description => $tkt->Subject(),
        tags        => $local_values->{'tags'}[0],
        observable  => $local_values->{'observable'}[0],
        protocol    => $local_values->{'protocol'}[0],
        portlist    => $local_values->{'portlist'}[0],
        confidence  => $local_values->{'confidence'}[0],
        reporttime  => $tkt->CreatedAsString(),
        altid       => RT->Config->Get('WebURL').'Ticket/Display.html?id='.$tkt->Id(),
        altid_tlp   => 'red',
    };
    
    return($report);
}	

1;