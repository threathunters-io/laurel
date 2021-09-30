include /usr/share/selinux/devel/Makefile

.PHONY: install
install: laurel.pp laurel.if
	install -d $(PREFIX)/usr/share/selinux/packages
	install -m 644 laurel.pp $(PREFIX)/usr/share/selinux/packages
	install -d $(PREFIX)/usr/share/selinux/devel/include/contrib
	install -m 644 laurel.if $(PREFIX)/usr/share/selinux/devel/include/contrib
	# install -d $(PREFIX)/etc/selinux/targeted/contexts/users/
	# install -m 644 laurel_u $(PREFIX)/etc/selinux/targeted/contexts/users/laurel_u
