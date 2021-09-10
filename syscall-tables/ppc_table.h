/* ppc_table.h --
 * Copyright 2005-09,2011-20 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

_S(1, "exit")
_S(2, "fork")
_S(3, "read")
_S(4, "write")
_S(5, "open")
_S(6, "close")
_S(7, "waitpid")
_S(8, "creat")
_S(9, "link")
_S(10, "unlink")
_S(11, "execve")
_S(12, "chdir")
_S(13, "time")
_S(14, "mknod")
_S(15, "chmod")
_S(16, "lchown")
_S(17, "break")
_S(18, "oldstat")
_S(19, "lseek")
_S(20, "getpid")
_S(21, "mount")
_S(22, "umount")
_S(23, "setuid")
_S(24, "getuid")
_S(25, "stime")
_S(26, "ptrace")
_S(27, "alarm")
_S(28, "oldfstat")
_S(29, "pause")
_S(30, "utime")
_S(31, "stty")
_S(32, "gtty")
_S(33, "access")
_S(34, "nice")
_S(35, "ftime")
_S(36, "sync")
_S(37, "kill")
_S(38, "rename")
_S(39, "mkdir")
_S(40, "rmdir")
_S(41, "dup")
_S(42, "pipe")
_S(43, "times")
_S(44, "prof")
_S(45, "brk")
_S(46, "setgid")
_S(47, "getgid")
_S(48, "signal")
_S(49, "geteuid")
_S(50, "getegid")
_S(51, "acct")
_S(52, "umount2")
_S(53, "lock")
_S(54, "ioctl")
_S(55, "fcntl")
_S(56, "mpx")
_S(57, "setpgid")
_S(58, "ulimit")
_S(59, "oldolduname")
_S(60, "umask")
_S(61, "chroot")
_S(62, "ustat")
_S(63, "dup2")
_S(64, "getppid")
_S(65, "getpgrp")
_S(66, "setsid")
_S(67, "sigaction")
_S(68, "sgetmask")
_S(69, "ssetmask")
_S(70, "setreuid")
_S(71, "setregid")
_S(72, "sigsuspend")
_S(73, "sigpending")
_S(74, "sethostname")
_S(75, "setrlimit")
_S(76, "getrlimit")
_S(77, "getrusage")
_S(78, "gettimeofday")
_S(79, "settimeofday")
_S(80, "getgroups")
_S(81, "setgroups")
_S(82, "select")
_S(83, "symlink")
_S(84, "oldlstat")
_S(85, "readlink")
_S(86, "uselib")
_S(87, "swapon")
_S(88, "reboot")
_S(89, "readdir")
_S(90, "mmap")
_S(91, "munmap")
_S(92, "truncate")
_S(93, "ftruncate")
_S(94, "fchmod")
_S(95, "fchown")
_S(96, "getpriority")
_S(97, "setpriority")
_S(98, "profil")
_S(99, "statfs")
_S(100, "fstatfs")
_S(101, "ioperm")
_S(102, "socketcall")
_S(103, "syslog")
_S(104, "setitimer")
_S(105, "getitimer")
_S(106, "stat")
_S(107, "lstat")
_S(108, "fstat")
_S(109, "olduname")
_S(110, "iopl")
_S(111, "vhangup")
_S(112, "idle")
_S(113, "vm86")
_S(114, "wait4")
_S(115, "swapoff")
_S(116, "sysinfo")
_S(117, "ipc")
_S(118, "fsync")
_S(119, "sigreturn")
_S(120, "clone")
_S(121, "setdomainname")
_S(122, "uname")
_S(123, "modify_ldt")
_S(124, "adjtimex")
_S(125, "mprotect")
_S(126, "sigprocmask")
_S(127, "create_module")
_S(128, "init_module")
_S(129, "delete_module")
_S(130, "get_kernel_syms")
_S(131, "quotactl")
_S(132, "getpgid")
_S(133, "fchdir")
_S(134, "bdflush")
_S(135, "sysfs")
_S(136, "personality")
_S(137, "afs_syscall")
_S(138, "setfsuid")
_S(139, "setfsgid")
_S(140, "_llseek")
_S(141, "getdents")
_S(142, "_newselect")
_S(143, "flock")
_S(144, "msync")
_S(145, "readv")
_S(146, "writev")
_S(147, "getsid")
_S(148, "fdatasync")
_S(149, "_sysctl")
_S(150, "mlock")
_S(151, "munlock")
_S(152, "mlockall")
_S(153, "munlockall")
_S(154, "sched_setparam")
_S(155, "sched_getparam")
_S(156, "sched_setscheduler")
_S(157, "sched_getscheduler")
_S(158, "sched_yield")
_S(159, "sched_get_priority_max")
_S(160, "sched_get_priority_min")
_S(161, "sched_rr_get_interval")
_S(162, "nanosleep")
_S(163, "mremap")
_S(164, "setresuid")
_S(165, "getresuid")
_S(166, "query_module")
_S(167, "poll")
_S(168, "nfsservctl")
_S(169, "setresgid")
_S(170, "getresgid")
_S(171, "prctl")
_S(172, "rt_sigreturn")
_S(173, "rt_sigaction")
_S(174, "rt_sigprocmask")
_S(175, "rt_sigpending")
_S(176, "rt_sigtimedwait")
_S(177, "rt_sigqueueinfo")
_S(178, "rt_sigsuspend")
_S(179, "pread")
_S(180, "pwrite")
_S(181, "chown")
_S(182, "getcwd")
_S(183, "capget")
_S(184, "capset")
_S(185, "sigaltstack")
_S(186, "sendfile")
_S(187, "getpmsg")
_S(188, "putpmsg")
_S(189, "vfork")
_S(190, "ugetrlimit")
_S(191, "readahead")
_S(192, "mmap2")
_S(193, "truncate64")
_S(194, "ftruncate64")
_S(195, "stat64")
_S(196, "lstat64")
_S(197, "fstat64")
_S(198, "pciconfig_read")
_S(199, "pciconfig_write")
_S(200, "pciconfig_iobase")
_S(201, "multiplexer")
_S(202, "getdents64")
_S(203, "pivot_root")
_S(204, "fcntl64")
_S(205, "madvise")
_S(206, "mincore")
_S(207, "gettid")
_S(208, "tkill")
_S(209, "setxattr")
_S(210, "lsetxattr")
_S(211, "fsetxattr")
_S(212, "getxattr")
_S(213, "lgetxattr")
_S(214, "fgetxattr")
_S(215, "listxattr")
_S(216, "llistxattr")
_S(217, "flistxattr")
_S(218, "removexattr")
_S(219, "lremovexattr")
_S(220, "fremovexattr")
_S(221, "futex")
_S(222, "sched_setaffinity")
_S(223, "sched_getaffinity")
_S(225, "tuxcall")
_S(226, "sendfile64")
_S(227, "io_setup")
_S(228, "io_destroy")
_S(229, "io_getevents")
_S(230, "io_submit")
_S(231, "io_cancel")
_S(232, "set_tid_address")
_S(233, "fadvise64")
_S(234, "exit_group")
_S(235, "lookup_dcookie")
_S(236, "epoll_create")
_S(237, "epoll_ctl")
_S(238, "epoll_wait")
_S(239, "remap_file_pages")
_S(240, "timer_create")
_S(241, "timer_settime")
_S(242, "timer_gettime")
_S(243, "timer_getoverrun")
_S(244, "timer_delete")
_S(245, "clock_settime")
_S(246, "clock_gettime")
_S(247, "clock_getres")
_S(248, "clock_nanosleep")
_S(249, "swapcontext")
_S(250, "tgkill")
_S(251, "utimes")
_S(252, "statfs64")
_S(253, "fstatfs64")
_S(254, "fadvise64_64")
_S(255, "rtas")
_S(262, "mq_open")
_S(263, "mq_unlink")
_S(264, "mq_timedsend")
_S(265, "mq_timedreceive")
_S(266, "mq_notify")
_S(267, "mq_getsetattr")
_S(268, "kexec_load")
_S(269, "add_key")
_S(270, "request_key")
_S(271, "keyctl")
_S(272, "waitid")
_S(273, "ioprio_set")
_S(274, "ioprio_get")
_S(275, "inotify_init")
_S(276, "inotify_add_watch")
_S(277, "inotify_rm_watch")
_S(278, "spu_run")
_S(279, "spu_create")
_S(280, "pselect6")
_S(281, "ppoll")
_S(282, "unshare")
_S(283, "splice")
_S(284, "tee")
_S(285, "vmsplice")
_S(286, "openat")
_S(287, "mkdirat")
_S(288, "mknodat")
_S(289, "fchownat")
_S(290, "futimesat")
_S(291, "fstatat64")
_S(292, "unlinkat")
_S(293, "renameat")
_S(294, "linkat")
_S(295, "symlinkat")
_S(296, "readlinkat")
_S(297, "fchmodat")
_S(298, "faccessat")
_S(299, "get_robust_list")
_S(300, "set_robust_list")
_S(301, "move_pages")
_S(302, "getcpu")
_S(303, "epoll_pwait")
_S(304, "utimensat")
_S(305, "signalfd")
_S(306, "timerfd")
_S(307, "eventfd")
_S(308, "sync_file_range2")
_S(309, "fallocate")
_S(310, "subpage_prot")
_S(311, "timerfd_settime")
_S(312, "timerfd_gettime")
_S(313, "signalfd4")
_S(314, "eventfd2")
_S(315, "epoll_create1")
_S(316, "dup3")
_S(317, "pipe2")
_S(318, "inotify_init1")
_S(319, "perf_counter_open")
_S(320, "preadv")
_S(321, "pwritev")
_S(322, "rt_tgsigqueueinfo")
_S(323, "fanotify_init")
_S(324, "fanotify_mark")
_S(325, "prlimit64")
_S(326, "socket")
_S(327, "bind")
_S(328, "connect")
_S(329, "listen")
_S(330, "accept")
_S(331, "getsockname")
_S(332, "getpeername")
_S(333, "socketpair")
_S(334, "send")
_S(335, "sendto")
_S(336, "recv")
_S(337, "recvfrom")
_S(338, "shutdown")
_S(339, "setsockopt")
_S(340, "getsockopt")
_S(341, "sendmsg")
_S(342, "recvmsg")
_S(343, "recvmmsg")
_S(344, "accept4")
_S(345, "name_to_handle_at")
_S(346, "open_by_handle_at")
_S(347, "clock_adjtime")
_S(348, "syncfs")
_S(349, "sendmmsg")
_S(350, "setns")
_S(351, "process_vm_readv")
_S(352, "process_vm_writev")
_S(353, "finit_module")
_S(354, "kcmp")
_S(355, "sched_setattr")
_S(356, "sched_getattr")
_S(357, "renameat2")
_S(358, "seccomp")
_S(359, "getrandom")
_S(360, "memfd_create")
_S(361, "bpf")
_S(362, "execveat")
_S(363, "switch_endian")
_S(364, "userfaultfd")
_S(365, "membarrier")
_S(378, "mlock2")
_S(379, "copy_file_range")
_S(380, "preadv2")
_S(381, "pwritev2")
_S(382, "kexec_file_load")
_S(383, "statx")
_S(384, "pkey_alloc")
_S(385, "pkey_free")
_S(386, "pkey_mprotect")
_S(387, "rseq")
_S(388, "io_pgetevents")
_S(392, "semtimedop")
_S(393, "semget")
_S(394, "semctl")
_S(395, "shmget")
_S(396, "shmctl")
_S(397, "shmat")
_S(398, "shmdt")
_S(399, "msgget")
_S(400, "msgsnd")
_S(401, "msgrcv")
_S(402, "msgctl")
_S(403, "clock_gettime64")
_S(404, "clock_settime64")
_S(405, "clock_adjtime64")
_S(406, "clock_getres_time64")
_S(407, "clock_nanosleep_time64")
_S(408, "timer_gettime64")
_S(409, "timer_settime64")
_S(410, "timerfd_gettime64")
_S(411, "timerfd_settime64")
_S(412, "utimensat_time64")
_S(413, "pselect6_time64")
_S(414, "ppoll_time64")
_S(416, "io_pgetevents_time64")
_S(417, "recvmmsg_time64")
_S(418, "mq_timedsend_time64")
_S(419, "mq_timedreceive_time64")
_S(420, "semtimedop_time64")
_S(421, "rt_sigtimedwait_time64")
_S(422, "futex_time64")
_S(423, "sched_rr_get_interval_time64")
_S(424, "pidfd_send_signal")
_S(425, "io_uring_setup")
_S(426, "io_uring_enter")
_S(427, "io_uring_register")
_S(428, "open_tree")
_S(429, "move_mount")
_S(430, "fsopen")
_S(431, "fsconfig")
_S(432, "fsmount")
_S(433, "fspick")
_S(434, "pidfd_open")
_S(435, "clone3")
_S(436, "close_range")
_S(437, "openat2")
_S(438, "pidfd_getfd")
_S(439, "faccessat2")
_S(440, "process_madvise")
_S(441, "epoll_pwait2")
_S(442, "mount_setattr")
_S(443, "quotactl_fd")
_S(444, "landlock_create_ruleset")
_S(445, "landlock_add_rule")
_S(446, "landlock_restrict_self")

