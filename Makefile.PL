use inc::Module::Install;

# fix lib paths, some may be relative
BEGIN {
    require File::Spec;
    my @libs = (
        "/opt/cif/lib",
        "/opt/rt3/local/plugins/RT-IODEF/lib",
        "../cif-v1/libcif/lib", # dev mode
    );
    my $bin_path;

    for my $lib (@libs) {
        unless ( File::Spec->file_name_is_absolute($lib) ) {
            unless ($bin_path) {
                if ( File::Spec->file_name_is_absolute(__FILE__) ) {
                    $bin_path = ( File::Spec->splitpath(__FILE__) )[1];
                }
                else {
                    require FindBin;
                    no warnings "once";
                    $bin_path = $FindBin::Bin;
                }
            }
            $lib = File::Spec->catfile( $bin_path, File::Spec->updir, $lib );
        }
        unshift @INC, $lib;
    }
}

RTx('RT-CIFMinimal');
license('GPL Version 2');
author('Barely3am Solutions <wes@barely3am.com>');
version_from('lib/RT/CIFMinimal.pm');

{ # check RT version
    my @v = split /\./, "$RT::VERSION";
    unless ($v[0]>=3 && $v[1]>=8 && ($v[2]>=1 || $v[2]eq'HEAD')) {
        die "RT-CIFMinimal and newer needs RT 3.8.10 at least, you have $RT::VERSION";
    }
}

# XXX: This should be reported by M::I::RTx
my ($lib_path) = $INC{'RT.pm'} =~ /^(.*)[\\\/]/;
my $local_lib_path = "$RT::LocalPath/lib";
unshift @INC, $local_lib_path, $lib_path;

requires('Regexp::Common'               => '2.122');
requires('Regexp::Common::net::CIDR'    => '0.02');
requires('Net::Abuse::Utils'            => '0.10');
requires('Net::CIDR'                    => '0.11');
requires('RT::IODEF'                    => '0.9901');
requires('CIF'                          => '1.00');
auto_install();

tests("t/*.t t/*/*.t");

WriteAll();
