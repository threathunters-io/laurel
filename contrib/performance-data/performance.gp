set xlabel "exec/s"
set ylabel "% cpu"
# set logscale xy
unset logscale
plot \
     "auditd-raw.dat"      using (1/$1):($2) lw 2 title "auditd 2.8.1 (RAW)"        with linespoints, \
     "auditd-enriched.dat" using (1/$1):($2) lw 2 title "auditd 2.8.1 (ENRICHED)"   with linespoints, \
     "laurel-0.1.3.dat"    using (1/$1):($2) lw 2 title "LAUREL 0.1.3"              with linespoints, \
     "go-audit-1.0.0.dat"  using (1/$1):($2) lw 2 title "go-audit 1.0.0"            with linespoints, \
     "auditbeat-7.12.dat"  using (1/$1):($2) lw 2 title "auditbeat 7.12.0"          with linespoints, \
     "sysmon-1.0.0.dat"    using (1/$1):($2) lw 2 title "Sysmon/Linux 1.0.0"        with linespoints, \

