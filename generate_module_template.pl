#!/usr/bin/env perl

use warnings;
use strict;

use feature qw(say);

use File::Slurp qw(read_file write_file);


sub get_args {
   my %opts = (
      kernel => $ENV{KERNELDIR}
   );

   return %opts;
}

sub get_informal_lsm_description {
   my $begin = index($_[0], '/**');
   my $end   = index($_[0], '*/', $begin);
   my $doc   = substr($_[0], $begin, $end - $begin);

   # remove leading '*'
   $doc =~ s/^\h+\*//mg;

   my %desc;
   while ($doc =~ m/ @(?<name>\w+):\h*\n(^\t.*\n)*/pmg) {
      my $name = $+{name};
      my $desc = ${^MATCH};

      # make it comment again
      $desc =~ s/^/ */gm;
      $desc = '/*' . $desc . ' */';
      $desc =~ s/\* \*/**/;

      $desc{$name} = $desc;
   }

   return %desc;
}

sub get_list_options_structure {
   if ($_[0] =~ m/union\h+security_list_options\h+{(?<lsm>[^}]++)};/) {
      my $seclist = $+{lsm};
      # split by ifdefs
      my @ifdef_order;
      my %lsm_ifdef;
      while ($seclist =~ m/#ifdef\s+(?<ifdef>\w+)([^#]*+)#endif/g) {
         push @ifdef_order, $+{ifdef};
         $lsm_ifdef{$+{ifdef}} = [$-[0], $+[0]];
      }
      my %lsm = (GENERAL => '');
      my $pos = 0;
      foreach my $ifdef (@ifdef_order) {
         my ($begin, $end) = $lsm_ifdef{$ifdef}->@*;

         $lsm{GENERAL} .= substr($seclist, $pos, $begin - $pos);
         $pos = $end;

         $lsm{$ifdef} = substr($seclist, $begin, $end - $begin);
      }

      foreach my $ifdef (keys %lsm) {
         my $list = $lsm{$ifdef};
         $lsm{$ifdef} = {};
         while ($list =~ m/(int|void)\s*\(\*(?<name>\w++)\)\s*\([^)]++\)\s*;/gp) {
            my $name = $+{name};
            my $type = ${^MATCH};
            $lsm{$ifdef}{$name} = $type;
         }
      }

      return %lsm;
   } else {
      die "Can't find security_list_options union\n";
   }
}

sub main {
   my %args = get_args();

   my $file = $args{kernel} . "/include/linux/lsm_hooks.h";
   die "Can't file $file\n"
      unless -r $file;

   my $hooks = read_file($file);

   my %doc = get_informal_lsm_description($hooks);
   my %lsm = get_list_options_structure($hooks);

   my $module = "#include \"acslinux.h\"\n\n";
   my $struct = "static struct security_hook_list acslinux_hooks[] __lsm_ro_after_init = {\n";
   foreach my $ifdef ('GENERAL', sort grep {$_ ne 'GENERAL'} keys %lsm) {
      my %funcs = $lsm{$ifdef}->%*;
      my $desc = '';
      my $list_hook = '';
      foreach my $f (sort keys %funcs) {
         my $type = $funcs{$f};
         my $name = 'acslinux_' . $f;
         my $func = $type =~ s/\(\s*\*\s*$f\s*\)/$name/r;
         my $args_begin = index($func, '(') + 1;
         my $args_end   = index($func, ')', $args_begin);
         my $args = substr($func, $args_begin, $args_end - $args_begin);
         $args =~ s/const|__user//g;
         $args =~ s/\s+/ /g;
         $args =~ s/(^\s+|\s+$)//g;
         my @pre;
         foreach my $arg (split m/,/, $args) {
            if ($arg =~ m/struct\h+(?<sname>\w+)\h*\*\h*(?<vname>\w+)/) {
               my $sname = $+{sname};
               my $vname = $+{vname};
               push @pre, "requires valid_$sname($vname);\n";
            } elsif ($arg =~ m/char\h*\*\h*(?<strname>\w+)/) {
               my $strname = $+{strname};
               push @pre, "requires valid_str($strname);\n";
            }
         }
         my $spec = '';
         if (@pre) {
            $spec = '/*@ ' . join('    ', @pre) . ' */';
         }
         $list_hook .= "\tLSM_HOOK_INIT($f, $name),\n";
         my $return = '';
         if ($type =~ m/^int/) {
            $return = "\treturn 0;\n";
         }
         $func =~ s/;/\n{\n$return}\n\n/;
         $func = "static " . $func;
         $func = $spec . "\n" . $func;
         if ($doc{$f}) {
            $func = $doc{$f} . "\n" . $func;
         }
         $desc .= "\n$func";
      }
      unless ($ifdef eq 'GENERAL') {
         $desc = "\n\n#ifdef $ifdef\n\n" . $desc . "#endif /* $ifdef */";
         $list_hook = "\n#ifdef $ifdef\n" . $list_hook . "#endif";
      }

      $module .= $desc;
      $struct .= $list_hook;
   }
   $struct .= "\n};";
   $module = $module . "\n\n" . $struct;

   print $module;
}

main();
