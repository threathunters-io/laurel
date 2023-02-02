# auditd 2.x and 3.x are different in how they launch plugins.
# Override AUDIT_AUDIT_VERSIONS to select only one variant.
AUDITD_VERSIONS = 2 3

include /usr/share/selinux/devel/Makefile

M4PARAM += $(foreach v,$(AUDITD_VERSIONS),-D audit$(v))

.PHONY: install
install: laurel.pp laurel.if
	install -d $(PREFIX)/usr/share/selinux/packages
	install -m 644 laurel.pp $(PREFIX)/usr/share/selinux/packages
	install -d $(PREFIX)/usr/share/selinux/devel/include/contrib
	install -m 644 laurel.if $(PREFIX)/usr/share/selinux/devel/include/contrib
	# install -d $(PREFIX)/etc/selinux/targeted/contexts/users/
	# install -m 644 laurel_u $(PREFIX)/etc/selinux/targeted/contexts/users/laurel_u
