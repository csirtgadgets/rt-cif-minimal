package RT::Action::CIFMinimal_ReopenReport;
use base 'RT::Action::Generic';

require RT::CIFMinimal;

sub Prepare { return 1; }

sub Commit {
	my $self = shift;
	
	my $tkt = $self->TicketObj();

    my $report = $self->TicketObj->IODEF();
    my $incident = @{$report->get_Incident()}[0];
    $incident->set_ReportTime(DateTime->from_epoch(epoch => time()));
    my ($err,$id) = RT::CIFMinimal::cif_submit({
        report  => $report,
        guid    => $tkt->FirstCustomFieldValue('Constituency') || $tkt->FirstCustomFieldValue('_RTIR_Constituency'),
    });
    if($err){
        $RT::Logger->warning($err);
        return;
    }
    return $id;
}

1;
