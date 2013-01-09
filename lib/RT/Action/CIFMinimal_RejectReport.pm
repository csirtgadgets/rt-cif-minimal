package RT::Action::CIFMinimal_RejectReport;
use base 'RT::Action::Generic';

require CIF::Archive;

sub Prepare { return 1; }

sub Commit {
	my $self = shift;

    my $r = $self->TicketObj->IODEF();

    my $ret;
    foreach(@$ret){
        $_->{'severity'} = 'low';
        $_->{'detecttime'} = DateTime->from_epoch(epoch => time());
        my ($err,$id) = CIF::Archive->insert($_);
        warn $err if($err);
        warn $id if($id);
    }
}

1;
