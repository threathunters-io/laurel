# _LAUREL_ Performance

While _LAUREL_ was written with performance in mind, running it on busy systems with audit rulesets that actually produce log entries does incur some CPU overhead. According to our measurements, CPU consumption by _auditd(8)_ 2.8, _audispd(8), and _LAUREL_ combined is about twice as high as with a simple _auditd(8)_ setup using the `log_format=ENRICHED` configuration option.

To put this into perspective, during our experiments we found that Elastic's _auditbeat_ consumed much more CPU time under the same circumstances -- about 2.5 times mroe than _LAUREL_.

We still see some optimization potential.
