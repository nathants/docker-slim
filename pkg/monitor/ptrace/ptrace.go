package ptrace

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/docker-slim/docker-slim/pkg/app/launcher"
	"github.com/docker-slim/docker-slim/pkg/errors"
	"github.com/docker-slim/docker-slim/pkg/report"
	"github.com/docker-slim/docker-slim/pkg/system"
)

type AppState string

const (
	AppStarted AppState = "app.started"
	AppFailed  AppState = "app.failed"
	AppDone    AppState = "app.done"
	AppExited  AppState = "app.exited"
)

// https://filippo.io/linux-syscall-table/
var syscalls = map[int]string{
	0:   "read",                   // sys_read                  fs/read_write.c
	1:   "write",                  // sys_write                 fs/read_write.c
	2:   "open",                   // sys_open                  fs/open.c
	3:   "close",                  // sys_close                 fs/open.c
	4:   "stat",                   // sys_newstat               fs/stat.c
	5:   "fstat",                  // sys_newfstat              fs/stat.c
	6:   "lstat",                  // sys_newlstat              fs/stat.c
	7:   "poll",                   // sys_poll                  fs/select.c
	8:   "lseek",                  // sys_lseek                 fs/read_write.c
	9:   "mmap",                   // sys_mmap                  arch/x86/kernel/sys_x86_64.c
	10:  "mprotect",               // sys_mprotect              mm/mprotect.c
	11:  "munmap",                 // sys_munmap                mm/mmap.c
	12:  "brk",                    // sys_brk                   mm/mmap.c
	13:  "rt_sigaction",           // sys_rt_sigaction          kernel/signal.c
	14:  "rt_sigprocmask",         // sys_rt_sigprocmask        kernel/signal.c
	15:  "rt_sigreturn",           // stub_rt_sigreturn         arch/x86/kernel/signal.c
	16:  "ioctl",                  // sys_ioctl                 fs/ioctl.c
	17:  "pread64",                // sys_pread64               fs/read_write.c
	18:  "pwrite64",               // sys_pwrite64              fs/read_write.c
	19:  "readv",                  // sys_readv                 fs/read_write.c
	20:  "writev",                 // sys_writev                fs/read_write.c
	21:  "access",                 // sys_access                fs/open.c
	22:  "pipe",                   // sys_pipe                  fs/pipe.c
	23:  "select",                 // sys_select                fs/select.c
	24:  "sched_yield",            // sys_sched_yield           kernel/sched/core.c
	25:  "mremap",                 // sys_mremap                mm/mmap.c
	26:  "msync",                  // sys_msync                 mm/msync.c
	27:  "mincore",                // sys_mincore               mm/mincore.c
	28:  "madvise",                // sys_madvise               mm/madvise.c
	29:  "shmget",                 // sys_shmget                ipc/shm.c
	30:  "shmat",                  // sys_shmat                 ipc/shm.c
	31:  "shmctl",                 // sys_shmctl                ipc/shm.c
	32:  "dup",                    // sys_dup                   fs/file.c
	33:  "dup2",                   // sys_dup2                  fs/file.c
	34:  "pause",                  // sys_pause                 kernel/signal.c
	35:  "nanosleep",              // sys_nanosleep             kernel/hrtimer.c
	36:  "getitimer",              // sys_getitimer             kernel/itimer.c
	37:  "alarm",                  // sys_alarm                 kernel/timer.c
	38:  "setitimer",              // sys_setitimer             kernel/itimer.c
	39:  "getpid",                 // sys_getpid                kernel/sys.c
	40:  "sendfile",               // sys_sendfile64            fs/read_write.c
	41:  "socket",                 // sys_socket                net/socket.c
	42:  "connect",                // sys_connect               net/socket.c
	43:  "accept",                 // sys_accept                net/socket.c
	44:  "sendto",                 // sys_sendto                net/socket.c
	45:  "recvfrom",               // sys_recvfrom              net/socket.c
	46:  "sendmsg",                // sys_sendmsg               net/socket.c
	47:  "recvmsg",                // sys_recvmsg               net/socket.c
	48:  "shutdown",               // sys_shutdown              net/socket.c
	49:  "bind",                   // sys_bind                  net/socket.c
	50:  "listen",                 // sys_listen                net/socket.c
	51:  "getsockname",            // sys_getsockname           net/socket.c
	52:  "getpeername",            // sys_getpeername           net/socket.c
	53:  "socketpair",             // sys_socketpair            net/socket.c
	54:  "setsockopt",             // sys_setsockopt            net/socket.c
	55:  "getsockopt",             // sys_getsockopt            net/socket.c
	56:  "clone",                  // stub_clone                kernel/fork.c
	57:  "fork",                   // stub_fork                 kernel/fork.c
	58:  "vfork",                  // stub_vfork                kernel/fork.c
	59:  "execve",                 // stub_execve               fs/exec.c
	60:  "exit",                   // sys_exit                  kernel/exit.c
	61:  "wait4",                  // sys_wait4                 kernel/exit.c
	62:  "kill",                   // sys_kill                  kernel/signal.c
	63:  "uname",                  // sys_newuname              kernel/sys.c
	64:  "semget",                 // sys_semget                ipc/sem.c
	65:  "semop",                  // sys_semop                 ipc/sem.c
	66:  "semctl",                 // sys_semctl                ipc/sem.c
	67:  "shmdt",                  // sys_shmdt                 ipc/shm.c
	68:  "msgget",                 // sys_msgget                ipc/msg.c
	69:  "msgsnd",                 // sys_msgsnd                ipc/msg.c
	70:  "msgrcv",                 // sys_msgrcv                ipc/msg.c
	71:  "msgctl",                 // sys_msgctl                ipc/msg.c
	72:  "fcntl",                  // sys_fcntl                 fs/fcntl.c
	73:  "flock",                  // sys_flock                 fs/locks.c
	74:  "fsync",                  // sys_fsync                 fs/sync.c
	75:  "fdatasync",              // sys_fdatasync             fs/sync.c
	76:  "truncate",               // sys_truncate              fs/open.c
	77:  "ftruncate",              // sys_ftruncate             fs/open.c
	78:  "getdents",               // sys_getdents              fs/readdir.c
	79:  "getcwd",                 // sys_getcwd                fs/dcache.c
	80:  "chdir",                  // sys_chdir                 fs/open.c
	81:  "fchdir",                 // sys_fchdir                fs/open.c
	82:  "rename",                 // sys_rename                fs/namei.c
	83:  "mkdir",                  // sys_mkdir                 fs/namei.c
	84:  "rmdir",                  // sys_rmdir                 fs/namei.c
	85:  "creat",                  // sys_creat                 fs/open.c
	86:  "link",                   // sys_link                  fs/namei.c
	87:  "unlink",                 // sys_unlink                fs/namei.c
	88:  "symlink",                // sys_symlink               fs/namei.c
	89:  "readlink",               // sys_readlink              fs/stat.c
	90:  "chmod",                  // sys_chmod                 fs/open.c
	91:  "fchmod",                 // sys_fchmod                fs/open.c
	92:  "chown",                  // sys_chown                 fs/open.c
	93:  "fchown",                 // sys_fchown                fs/open.c
	94:  "lchown",                 // sys_lchown                fs/open.c
	95:  "umask",                  // sys_umask                 kernel/sys.c
	96:  "gettimeofday",           // sys_gettimeofday          kernel/time.c
	97:  "getrlimit",              // sys_getrlimit             kernel/sys.c
	98:  "getrusage",              // sys_getrusage             kernel/sys.c
	99:  "sysinfo",                // sys_sysinfo               kernel/sys.c
	100: "times",                  // sys_times                 kernel/sys.c
	101: "ptrace",                 // sys_ptrace                kernel/ptrace.c
	102: "getuid",                 // sys_getuid                kernel/sys.c
	103: "syslog",                 // sys_syslog                kernel/printk/printk.c
	104: "getgid",                 // sys_getgid                kernel/sys.c
	105: "setuid",                 // sys_setuid                kernel/sys.c
	106: "setgid",                 // sys_setgid                kernel/sys.c
	107: "geteuid",                // sys_geteuid               kernel/sys.c
	108: "getegid",                // sys_getegid               kernel/sys.c
	109: "setpgid",                // sys_setpgid               kernel/sys.c
	110: "getppid",                // sys_getppid               kernel/sys.c
	111: "getpgrp",                // sys_getpgrp               kernel/sys.c
	112: "setsid",                 // sys_setsid                kernel/sys.c
	113: "setreuid",               // sys_setreuid              kernel/sys.c
	114: "setregid",               // sys_setregid              kernel/sys.c
	115: "getgroups",              // sys_getgroups             kernel/groups.c
	116: "setgroups",              // sys_setgroups             kernel/groups.c
	117: "setresuid",              // sys_setresuid             kernel/sys.c
	118: "getresuid",              // sys_getresuid             kernel/sys.c
	119: "setresgid",              // sys_setresgid             kernel/sys.c
	120: "getresgid",              // sys_getresgid             kernel/sys.c
	121: "getpgid",                // sys_getpgid               kernel/sys.c
	122: "setfsuid",               // sys_setfsuid              kernel/sys.c
	123: "setfsgid",               // sys_setfsgid              kernel/sys.c
	124: "getsid",                 // sys_getsid                kernel/sys.c
	125: "capget",                 // sys_capget                kernel/capability.c
	126: "capset",                 // sys_capset                kernel/capability.c
	127: "rt_sigpending",          // sys_rt_sigpending         kernel/signal.c
	128: "rt_sigtimedwait",        // sys_rt_sigtimedwait       kernel/signal.c
	129: "rt_sigqueueinfo",        // sys_rt_sigqueueinfo       kernel/signal.c
	130: "rt_sigsuspend",          // sys_rt_sigsuspend         kernel/signal.c
	131: "sigaltstack",            // sys_sigaltstack           kernel/signal.c
	132: "utime",                  // sys_utime                 fs/utimes.c
	133: "mknod",                  // sys_mknod                 fs/namei.c
	134: "uselib",                 // fs                      /eec.c
	135: "personality",            // sys_personality           kernel/exec_domain.c
	136: "ustat",                  // sys_ustat                 fs/statfs.c
	137: "statfs",                 // sys_statfs                fs/statfs.c
	138: "fstatfs",                // sys_fstatfs               fs/statfs.c
	139: "sysfs",                  // sys_sysfs                 fs/filesystems.c
	140: "getpriority",            // sys_getpriority           kernel/sys.c
	141: "setpriority",            // sys_setpriority           kernel/sys.c
	142: "sched_setparam",         // sys_sched_setparam        kernel/sched/core.c
	143: "sched_getparam",         // sys_sched_getparam        kernel/sched/core.c
	144: "sched_setscheduler",     // sys_sched_setscheduler    kernel/sched/core.c
	145: "sched_getscheduler",     // sys_sched_getscheduler    kernel/sched/core.c
	146: "sched_get_priority_max", // sys_sched_get_priority_maxkernel/sched/core.c
	147: "sched_get_priority_min", // sys_sched_get_priority_minkernel/sched/core.c
	148: "sched_rr_get_interval",  // sys_sched_rr_get_interval kernel/sched/core.c
	149: "mlock",                  // sys_mlock                 mm/mlock.c
	150: "munlock",                // sys_munlock               mm/mlock.c
	151: "mlockall",               // sys_mlockall              mm/mlock.c
	152: "munlockall",             // sys_munlockall            mm/mlock.c
	153: "vhangup",                // sys_vhangup               fs/open.c
	154: "modify_ldt",             // sys_modify_ldt            arch/x86/um/ldt.c
	155: "pivot_root",             // sys_pivot_root            fs/namespace.c
	156: "_sysctl",                // sys_sysctl                kernel/sysctl_binary.c
	157: "prctl",                  // sys_prctl                 kernel/sys.c
	158: "arch_prctl",             // sys_arch_prctl            arch/x86/um/syscalls_64.c
	159: "adjtimex",               // sys_adjtimex              kernel/time.c
	160: "setrlimit",              // sys_setrlimit             kernel/sys.c
	161: "chroot",                 // sys_chroot                fs/open.c
	162: "sync",                   // sys_sync                  fs/sync.c
	163: "acct",                   // sys_acct                  kernel/acct.c
	164: "settimeofday",           // sys_settimeofday          kernel/time.c
	165: "mount",                  // sys_mount                 fs/namespace.c
	166: "umount2",                // sys_umount                fs/namespace.c
	167: "swapon",                 // sys_swapon                mm/swapfile.c
	168: "swapoff",                // sys_swapoff               mm/swapfile.c
	169: "reboot",                 // sys_reboot                kernel/reboot.c
	170: "sethostname",            // sys_sethostname           kernel/sys.c
	171: "setdomainname",          // sys_setdomainname         kernel/sys.c
	172: "iopl",                   // stub_iopl                 arch/x86/kernel/ioport.c
	173: "ioperm",                 // sys_ioperm                arch/x86/kernel/ioport.c
	174: "create_module",          // NOT IMPLEMENTED
	175: "init_module",            // sys_init_module           kernel/module.c
	176: "delete_module",          // sys_delete_module         kernel/module.c
	177: "get_kernel_syms",        // NOT IMPLEMENTED
	178: "query_module",           // NOT IMPLEMENTED
	179: "quotactl",               // sys_quotactl              fs/quota/quota.c
	180: "nfsservctl",             // NOT IMPLEMENTED
	181: "getpmsg",                // NOT IMPLEMENTED
	182: "putpmsg",                // NOT IMPLEMENTED
	183: "afs_syscall",            // NOT IMPLEMENTED
	184: "tuxcall",                // NOT IMPLEMENTED
	185: "security",               // NOT IMPLEMENTED
	186: "gettid",                 // sys_gettid                kernel/sys.c
	187: "readahead",              // sys_readahead             mm/readahead.c
	188: "setxattr",               // sys_setxattr              fs/xattr.c
	189: "lsetxattr",              // sys_lsetxattr             fs/xattr.c
	190: "fsetxattr",              // sys_fsetxattr             fs/xattr.c
	191: "getxattr",               // sys_getxattr              fs/xattr.c
	192: "lgetxattr",              // sys_lgetxattr             fs/xattr.c
	193: "fgetxattr",              // sys_fgetxattr             fs/xattr.c
	194: "listxattr",              // sys_listxattr             fs/xattr.c
	195: "llistxattr",             // sys_llistxattr            fs/xattr.c
	196: "flistxattr",             // sys_flistxattr            fs/xattr.c
	197: "removexattr",            // sys_removexattr           fs/xattr.c
	198: "lremovexattr",           // sys_lremovexattr          fs/xattr.c
	199: "fremovexattr",           // sys_fremovexattr          fs/xattr.c
	200: "tkill",                  // sys_tkill                 kernel/signal.c
	201: "time",                   // sys_time                  kernel/time.c
	202: "futex",                  // sys_futex                 kernel/futex.c
	203: "sched_setaffinity",      // sys_sched_setaffinity     kernel/sched/core.c
	204: "sched_getaffinity",      // sys_sched_getaffinity     kernel/sched/core.c
	205: "set_thread_area",        // arch                      x86/kernel/tls.c
	206: "io_setup",               // sys_io_setup              fs/aio.c
	207: "io_destroy",             // sys_io_destroy            fs/aio.c
	208: "io_getevents",           // sys_io_getevents          fs/aio.c
	209: "io_submit",              // sys_io_submit             fs/aio.c
	210: "io_cancel",              // sys_io_cancel             fs/aio.c
	211: "get_thread_area",        // arch                      x86/kernel/tls.c
	212: "lookup_dcookie",         // sys_lookup_dcookie        fs/dcookies.c
	213: "epoll_create",           // sys_epoll_create          fs/eventpoll.c
	214: "epoll_ctl_old",          // NOT IMPLEMENTED
	215: "epoll_wait_old",         // NOT IMPLEMENTED
	216: "remap_file_pages",       // sys_remap_file_pages      mm/fremap.c
	217: "getdents64",             // sys_getdents64            fs/readdir.c
	218: "set_tid_address",        // sys_set_tid_address       kernel/fork.c
	219: "restart_syscall",        // sys_restart_syscall       kernel/signal.c
	220: "semtimedop",             // sys_semtimedop            ipc/sem.c
	221: "fadvise64",              // sys_fadvise64             mm/fadvise.c
	222: "timer_create",           // sys_timer_create          kernel/posix-timers.c
	223: "timer_settime",          // sys_timer_settime         kernel/posix-timers.c
	224: "timer_gettime",          // sys_timer_gettime         kernel/posix-timers.c
	225: "timer_getoverrun",       // sys_timer_getoverrun      kernel/posix-timers.c
	226: "timer_delete",           // sys_timer_delete          kernel/posix-timers.c
	227: "clock_settime",          // sys_clock_settime         kernel/posix-timers.c
	228: "clock_gettime",          // sys_clock_gettime         kernel/posix-timers.c
	229: "clock_getres",           // sys_clock_getres          kernel/posix-timers.c
	230: "clock_nanosleep",        // sys_clock_nanosleep       kernel/posix-timers.c
	231: "exit_group",             // sys_exit_group            kernel/exit.c
	232: "epoll_wait",             // sys_epoll_wait            fs/eventpoll.c
	233: "epoll_ctl",              // sys_epoll_ctl             fs/eventpoll.c
	234: "tgkill",                 // sys_tgkill                kernel/signal.c
	235: "utimes",                 // sys_utimes                fs/utimes.c
	236: "vserver",                // NOT IMPLEMENTED
	237: "mbind",                  // sys_mbind                 mm/mempolicy.c
	238: "set_mempolicy",          // sys_set_mempolicy         mm/mempolicy.c
	239: "get_mempolicy",          // sys_get_mempolicy         mm/mempolicy.c
	240: "mq_open",                // sys_mq_open               ipc/mqueue.c
	241: "mq_unlink",              // sys_mq_unlink             ipc/mqueue.c
	242: "mq_timedsend",           // sys_mq_timedsend          ipc/mqueue.c
	243: "mq_timedreceive",        // sys_mq_timedreceive       ipc/mqueue.c
	244: "mq_notify",              // sys_mq_notify             ipc/mqueue.c
	245: "mq_getsetattr",          // sys_mq_getsetattr         ipc/mqueue.c
	246: "kexec_load",             // sys_kexec_load            kernel/kexec.c
	247: "waitid",                 // sys_waitid                kernel/exit.c
	248: "add_key",                // sys_add_key               security/keys/keyctl.c
	249: "request_key",            // sys_request_key           security/keys/keyctl.c
	250: "keyctl",                 // sys_keyctl                security/keys/keyctl.c
	251: "ioprio_set",             // sys_ioprio_set            fs/ioprio.c
	252: "ioprio_get",             // sys_ioprio_get            fs/ioprio.c
	253: "inotify_init",           // sys_inotify_init          fs/notify/inotify/inotify_user.c
	254: "inotify_add_watch",      // sys_inotify_add_watch     fs/notify/inotify/inotify_user.c
	255: "inotify_rm_watch",       // sys_inotify_rm_watch      fs/notify/inotify/inotify_user.c
	256: "migrate_pages",          // sys_migrate_pages         mm/mempolicy.c
	257: "openat",                 // sys_openat                fs/open.c
	258: "mkdirat",                // sys_mkdirat               fs/namei.c
	259: "mknodat",                // sys_mknodat               fs/namei.c
	260: "fchownat",               // sys_fchownat              fs/open.c
	261: "futimesat",              // sys_futimesat             fs/utimes.c
	262: "newfstatat",             // sys_newfstatat            fs/stat.c
	263: "unlinkat",               // sys_unlinkat              fs/namei.c
	264: "renameat",               // sys_renameat              fs/namei.c
	265: "linkat",                 // sys_linkat                fs/namei.c
	266: "symlinkat",              // sys_symlinkat             fs/namei.c
	267: "readlinkat",             // sys_readlinkat            fs/stat.c
	268: "fchmodat",               // sys_fchmodat              fs/open.c
	269: "faccessat",              // sys_faccessat             fs/open.c
	270: "pselect6",               // sys_pselect6              fs/select.c
	271: "ppoll",                  // sys_ppoll                 fs/select.c
	272: "unshare",                // sys_unshare               kernel/fork.c
	273: "set_robust_list",        // sys_set_robust_list       kernel/futex.c
	274: "get_robust_list",        // sys_get_robust_list       kernel/futex.c
	275: "splice",                 // sys_splice                fs/splice.c
	276: "tee",                    // sys_tee                   fs/splice.c
	277: "sync_file_range",        // sys_sync_file_range       fs/sync.c
	278: "vmsplice",               // sys_vmsplice              fs/splice.c
	279: "move_pages",             // sys_move_pages            mm/migrate.c
	280: "utimensat",              // sys_utimensat             fs/utimes.c
	281: "epoll_pwait",            // sys_epoll_pwait           fs/eventpoll.c
	282: "signalfd",               // sys_signalfd              fs/signalfd.c
	283: "timerfd_create",         // sys_timerfd_create        fs/timerfd.c
	284: "eventfd",                // sys_eventfd               fs/eventfd.c
	285: "fallocate",              // sys_fallocate             fs/open.c
	286: "timerfd_settime",        // sys_timerfd_settime       fs/timerfd.c
	287: "timerfd_gettime",        // sys_timerfd_gettime       fs/timerfd.c
	288: "accept4",                // sys_accept4               net/socket.c
	289: "signalfd4",              // sys_signalfd4             fs/signalfd.c
	290: "eventfd2",               // sys_eventfd2              fs/eventfd.c
	291: "epoll_create1",          // sys_epoll_create1         fs/eventpoll.c
	292: "dup3",                   // sys_dup3                  fs/file.c
	293: "pipe2",                  // sys_pipe2                 fs/pipe.c
	294: "inotify_init1",          // sys_inotify_init1         fs/notify/inotify/inotify_user.c
	295: "preadv",                 // sys_preadv                fs/read_write.c
	296: "pwritev",                // sys_pwritev               fs/read_write.c
	297: "rt_tgsigqueueinfo",      // sys_rt_tgsigqueueinfo     kernel/signal.c
	298: "perf_event_open",        // sys_perf_event_open       kernel/events/core.c
	299: "recvmmsg",               // sys_recvmmsg              net/socket.c
	300: "fanotify_init",          // sys_fanotify_init         fs/notify/fanotify/fanotify_user.c
	301: "fanotify_mark",          // sys_fanotify_mark         fs/notify/fanotify/fanotify_user.c
	302: "prlimit64",              // sys_prlimit64             kernel/sys.c
	303: "name_to_handle_at",      // sys_name_to_handle_at     fs/fhandle.c
	304: "open_by_handle_at",      // sys_open_by_handle_at     fs/fhandle.c
	305: "clock_adjtime",          // sys_clock_adjtime         kernel/posix-timers.c
	306: "syncfs",                 // sys_syncfs                fs/sync.c
	307: "sendmmsg",               // sys_sendmmsg              net/socket.c
	308: "setns",                  // sys_setns                 kernel/nsproxy.c
	309: "getcpu",                 // sys_getcpu                kernel/sys.c
	310: "process_vm_readv",       // sys_process_vm_readv      mm/process_vm_access.c
	311: "process_vm_writev",      // sys_process_vm_writev     mm/process_vm_access.c
	312: "kcmp",                   // sys_kcmp                  kernel/kcmp.c
	313: "finit_module",           // sys_finit_module          kernel/module.c
}

func Run(
	cmd string,
	args []string,
	dir string,
	user string,
	runAsUser bool,
	reportCh chan *report.PtMonitorReport,
	errorCh chan error,
	stateCh chan AppState,
	stopCh chan struct{},
) (*App, error) {
	log.Debug("ptrace.Run")
	app, err := newApp(cmd, args, dir, user, runAsUser, reportCh, errorCh, stateCh, stopCh)
	if err != nil {
		app.StateCh <- AppFailed
		return nil, err
	}

	go app.process()
	go app.trace()

	return app, nil
}

const ptOptions = syscall.PTRACE_O_TRACECLONE |
	syscall.PTRACE_O_TRACEFORK |
	syscall.PTRACE_O_TRACEVFORK |
	syscall.PTRACE_O_TRACEEXEC |
	syscall.PTRACE_O_TRACESYSGOOD |
	syscall.PTRACE_O_TRACEEXIT |
	unix.PTRACE_O_EXITKILL

type syscallState struct {
	pid          int
	callNum      uint64
	retVal       uint64
	expectReturn bool
	gotCallNum   bool
	gotRetVal    bool
	started      bool
	exiting      bool
}

type App struct {
	Cmd             string
	Args            []string
	Dir             string
	User            string
	RunAsUser       bool
	Report          report.PtMonitorReport
	ReportCh        chan *report.PtMonitorReport
	ErrorCh         chan error
	StateCh         chan AppState
	StopCh          chan struct{}
	syscallCounters map[uint32]uint64
	syscallResolver system.NumberResolverFunc
	cmd             *exec.Cmd
	pgid            int
	eventCh         chan syscallEvent
	collectorDoneCh chan int
}

func (a *App) MainPID() int {
	return a.cmd.Process.Pid
}

func (a *App) PGID() int {
	return a.pgid
}

const eventBufSize = 2000

type syscallEvent struct {
	pid     int
	callNum uint32
	retVal  uint64
}

func newApp(cmd string,
	args []string,
	dir string,
	user string,
	runAsUser bool,
	reportCh chan *report.PtMonitorReport,
	errorCh chan error,
	stateCh chan AppState,
	stopCh chan struct{}) (*App, error) {
	log.Debug("ptrace.newApp")
	if reportCh == nil {
		reportCh = make(chan *report.PtMonitorReport, 1)
	}

	if errorCh == nil {
		errorCh = make(chan error, 100)
	}

	if stateCh == nil {
		stateCh = make(chan AppState, 10)
	}

	if stopCh == nil {
		stopCh = make(chan struct{})
	}

	sysInfo := system.GetSystemInfo()
	archName := system.MachineToArchName(sysInfo.Machine)

	a := App{
		Cmd:             cmd,
		Args:            args,
		Dir:             dir,
		User:            user,
		RunAsUser:       runAsUser,
		ReportCh:        reportCh,
		ErrorCh:         errorCh,
		StateCh:         stateCh,
		StopCh:          stopCh,
		syscallCounters: map[uint32]uint64{},
		eventCh:         make(chan syscallEvent, eventBufSize),
		collectorDoneCh: make(chan int, 1),
		syscallResolver: system.CallNumberResolver(archName),
		Report: report.PtMonitorReport{
			ArchName:     string(archName),
			SyscallStats: map[string]report.SyscallStatInfo{},
		},
	}

	return &a, nil
}

func (app *App) Stop() {
	close(app.StopCh)
}

func (app *App) trace() {
	log.Debug("ptrace.App.trace")
	runtime.LockOSThread()

	err := app.start()
	if err != nil {
		app.collectorDoneCh <- 1
		app.StateCh <- AppFailed
		app.ErrorCh <- errors.SE("ptrace.App.trace.app.start", "call.error", err)
		return
	}

	app.StateCh <- AppStarted
	app.collect()
}

func (app *App) process() {
	log.Debug("ptrace.App.process")
	state := AppDone

done:
	for {
		select {
		case rc := <-app.collectorDoneCh:
			log.Debugf("ptrace.App.process: collector finished => %v", rc)
			if rc > 0 {
				state = AppFailed
			}
			break done
		case <-app.StopCh:
			log.Debug("ptrace.App.process: stopping...")
			//NOTE: need a better way to stop the target app...
			//"os: process already finished" error is ok
			if err := app.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				log.Debug("ptrace.App.process: error stopping target app => ", err)
				if err := app.cmd.Process.Kill(); err != nil {
					log.Debug("ptrace.App.process: error killing target app => ", err)
				}
			}
			break done
		case e := <-app.eventCh:
			app.Report.SyscallCount++
			log.Debugf("ptrace.App.process: event ==> {pid=%v cn=%d}", e.pid, e.callNum)

			if _, ok := app.syscallCounters[e.callNum]; ok {
				app.syscallCounters[e.callNum]++
			} else {
				app.syscallCounters[e.callNum] = 1
			}
		}
	}

	log.Debugf("ptrace.App.process: - executed syscall count = %d", app.Report.SyscallCount)
	log.Debugf("ptrace.App.process: - number of syscalls: %v", len(app.syscallCounters))

	for scNum, scCount := range app.syscallCounters {
		syscallName := app.syscallResolver(scNum)
		log.Debugf("[%v] %v = %v", scNum, syscallName, scCount)
		scKey := strconv.FormatInt(int64(scNum), 10)
		app.Report.SyscallStats[scKey] = report.SyscallStatInfo{
			Number: scNum,
			Name:   syscallName,
			Count:  scCount,
		}
	}

	app.Report.SyscallNum = uint32(len(app.Report.SyscallStats))

	app.StateCh <- state
	app.ReportCh <- &app.Report
}

func (app *App) start() error {
	log.Debug("ptrace.App.start")
	var err error

	app.cmd, err = launcher.Start(app.Cmd, app.Args, app.Dir, app.User, app.RunAsUser, true)
	if err != nil {
		log.Errorf("ptrace.App.start: cmd='%v' args='%+v' dir='%v' error=%v\n",
			app.Cmd, app.Args, app.Dir, err)
		return err
	}

	err = app.cmd.Wait()
	log.Debugf("ptrace.App.start: app.cmd.Wait err - %v", err)
	log.Debugf("ptrace.App.start: Process state info - Exited=%v ExitCode=%v SysWaitStatus=%v",
		app.cmd.ProcessState.Exited(),
		app.cmd.ProcessState.ExitCode(),
		app.cmd.ProcessState.Sys())

	waitStatus, ok := app.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ok {
		log.Debugf("ptrace.App.start: Process wait status - %v (Exited=%v Signaled=%v Signal='%v' Stopped=%v StopSignal='%v' TrapCause=%v)",
			waitStatus,
			waitStatus.Exited(),
			waitStatus.Signaled(),
			waitStatus.Signal(),
			waitStatus.Stopped(),
			waitStatus.StopSignal(),
			waitStatus.TrapCause())

		if waitStatus.Exited() {
			log.Debug("ptrace.App.start: unexpected app exit")
			return fmt.Errorf("unexpected app exit")
		}

		if waitStatus.Signaled() {
			log.Debug("ptrace.App.start: unexpected app signalled")
			return fmt.Errorf("unexpected app signalled")
		}

		//we should be in the Stopped state
		if waitStatus.Stopped() {
			sigEnum := SignalEnum(int(waitStatus.StopSignal()))
			log.Debugf("ptrace.App.start: Process Stop Signal - code=%d enum=%s str=%s",
				waitStatus.StopSignal(), sigEnum, waitStatus.StopSignal())
		} else {
			//TODO:
			//check for Exited or Signaled process state (shouldn't happen)
			//do it for context indicating that we are in a failed state
		}
	} else {
		return fmt.Errorf("process status error")
	}

	app.pgid, err = syscall.Getpgid(app.cmd.Process.Pid)
	if err != nil {
		return err
	}

	log.Debugf("ptrace.App.start: started target app --> PID=%d PGID=%d",
		app.cmd.Process.Pid, app.pgid)

	err = syscall.PtraceSetOptions(app.cmd.Process.Pid, ptOptions)
	if err != nil {
		return err
	}

	return nil
}

const traceSysGoodStatusBit = 0x80

func StopSignalInfo(sig syscall.Signal) string {
	sigNum := int(sig)
	if sigNum == -1 {
		return fmt.Sprintf("(code=%d)", sigNum)
	}

	sigEnum := SignalEnum(sigNum)
	sigStr := sig.String()
	if sig&traceSysGoodStatusBit == traceSysGoodStatusBit {
		msig := sig &^ traceSysGoodStatusBit
		sigEnum = fmt.Sprintf("%s|0x%04x", SignalEnum(int(msig)), traceSysGoodStatusBit)
		sigStr = fmt.Sprintf("%s|0x%04x", msig, traceSysGoodStatusBit)
	}

	info := fmt.Sprintf("(code=%d/0x%04x enum='%s' str='%s')",
		sigNum, sigNum, sigEnum, sigStr)

	return info
}

func SigTrapCauseInfo(cause int) string {
	if cause == -1 {
		return fmt.Sprintf("(code=%d)", cause)
	}

	causeEnum := PtraceEvenEnum(cause)
	info := fmt.Sprintf("(code=%d enum=%s)", cause, causeEnum)

	return info
}

func PtraceEvenEnum(data int) string {
	if enum, ok := ptEventMap[data]; ok {
		return enum
	} else {
		return fmt.Sprintf("(%d)", data)
	}
}

var ptEventMap = map[int]string{
	syscall.PTRACE_EVENT_CLONE:      "PTRACE_EVENT_CLONE",
	syscall.PTRACE_EVENT_EXEC:       "PTRACE_EVENT_EXEC",
	syscall.PTRACE_EVENT_EXIT:       "PTRACE_EVENT_EXIT",
	syscall.PTRACE_EVENT_FORK:       "PTRACE_EVENT_FORK",
	unix.PTRACE_EVENT_SECCOMP:       "PTRACE_EVENT_SECCOMP",
	unix.PTRACE_EVENT_STOP:          "PTRACE_EVENT_STOP",
	syscall.PTRACE_EVENT_VFORK:      "PTRACE_EVENT_VFORK",
	syscall.PTRACE_EVENT_VFORK_DONE: "PTRACE_EVENT_VFORK_DONE",
}

func (app *App) collect() {
	log.Debug("ptrace.App.collect")
	callPid := app.MainPID()
	prevPid := callPid

	log.Tracef("ptrace.App.collect: trace syscall mainPID=%v", callPid)

	pidSyscallState := map[int]*syscallState{}
	pidSyscallState[callPid] = &syscallState{pid: callPid}

	mainExiting := false
	waitFor := -1
	doSyscall := true
	for {
		var callSig int

		select {
		case <-app.StopCh:
			log.Debug("ptrace.App.collect: stop (exiting)")
			return
		default:
		}

		if doSyscall {
			log.Tracef("ptrace.App.collect: trace syscall (pid=%v sig=%v)", callPid, callSig)
			err := syscall.PtraceSyscall(callPid, callSig)
			if err != nil {
				log.Errorf("ptrace.App.collect: trace syscall pid=%v sig=%v error - %v (errno=%d)", callPid, callSig, err, err.(syscall.Errno))
				app.ErrorCh <- errors.SE("ptrace.App.collect.ptsyscall", "call.error", err)
				//keep waiting for other syscalls
			}
		}

		log.Trace("ptrace.App.collect: waiting for syscall...")
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(waitFor, &ws, syscall.WALL, nil)
		if err != nil {
			if err.(syscall.Errno) == syscall.ECHILD {
				log.Debug("ptrace.App.collect: wait4 ECHILD error (ignoring)")
				doSyscall = false
				continue
			}

			log.Debugf("ptrace.App.collect: wait4 error - %v (errno=%d)", err, err.(syscall.Errno))
			app.ErrorCh <- errors.SE("ptrace.App.collect.wait4", "call.error", err)
			app.StateCh <- AppFailed
			app.collectorDoneCh <- 2
			return
		}

		log.Tracef("ptrace.App.collect: wait4 -> wpid=%v wstatus=%v (Exited=%v Signaled=%v Signal='%v' Stopped=%v StopSignalInfo=%s TrapCause=%s)",
			wpid,
			ws,
			ws.Exited(),
			ws.Signaled(),
			ws.Signal(),
			ws.Stopped(),
			StopSignalInfo(ws.StopSignal()),
			SigTrapCauseInfo(ws.TrapCause()))

		if wpid == -1 {
			log.Error("ptrace.App.collect: wpid = -1")
			app.StateCh <- AppFailed
			app.ErrorCh <- errors.SE("ptrace.App.collect.wpid", "call.error", fmt.Errorf("wpid is -1"))
			return
		}

		terminated := false
		stopped := false
		eventStop := false
		handleCall := false
		eventCode := 0
		statusCode := 0
		switch {
		case ws.Exited():
			terminated = true
			statusCode = ws.ExitStatus()
		case ws.Signaled():
			terminated = true
			statusCode = int(ws.Signal())
		case ws.Stopped():
			stopped = true
			statusCode = int(ws.StopSignal())
			if statusCode == int(syscall.SIGTRAP|traceSysGoodStatusBit) {
				handleCall = true
			} else if statusCode == int(syscall.SIGTRAP) {
				eventStop = true
				eventCode = ws.TrapCause()
			} else {
				callSig = statusCode
			}
		}

		if terminated {
			if _, ok := pidSyscallState[wpid]; !ok {
				log.Debugf("ptrace.App.collect: unknown process is terminated (%v)", wpid)
			} else {
				if !pidSyscallState[wpid].exiting {
					log.Debugf("ptrace.App.collect: unexpected process termination (%v)", wpid)
				}
			}

			delete(pidSyscallState, wpid)
			if app.MainPID() == wpid {
				log.Debug("ptrace.App.collect: wpid is main PID and terminated...")
				if !mainExiting {
					log.Debug("ptrace.App.collect: unexpected main PID termination...")
				}
			}

			if len(pidSyscallState) == 0 {
				log.Debug("ptrace.App.collect: all processes terminated...")
				app.collectorDoneCh <- 0
				return
			}

			doSyscall = false
			continue
		}

		if handleCall {
			var cstate *syscallState
			if _, ok := pidSyscallState[wpid]; ok {
				cstate = pidSyscallState[wpid]
			} else {
				log.Debugf("ptrace.App.collect: collector loop - new pid - mainPid=%v pid=%v (prevPid=%v) - add state", app.MainPID(), wpid, prevPid)
				//TODO: create new process records from clones/forks
				cstate = &syscallState{pid: wpid}
				pidSyscallState[wpid] = cstate
			}

			if !cstate.expectReturn {
				if err := onSyscall(wpid, cstate); err != nil {
					log.Debugf("ptrace.App.collect: onSyscall error - %v", err)
					continue
				}
			} else {
				if err := onSyscallReturn(wpid, cstate); err != nil {
					log.Debugf("ptrace.App.collect: onSyscallReturn error - %v", err)
					continue
				}
			}

			if cstate.gotCallNum && cstate.gotRetVal {
				cstate.gotCallNum = false
				cstate.gotRetVal = false

				evt := syscallEvent{
					pid:     wpid,
					callNum: uint32(cstate.callNum),
					retVal:  cstate.retVal,
				}

				select {
				case app.eventCh <- evt:
				default:
					log.Debugf("ptrace.App.collect: app.eventCh send error (%#v)", evt)
				}
			}
		}

		if eventStop {
			log.Debugf("ptrace.App.collect: eventStop eventCode=%d(0x%04x)", eventCode, eventCode)

			switch eventCode {
			case syscall.PTRACE_EVENT_CLONE,
				syscall.PTRACE_EVENT_FORK,
				syscall.PTRACE_EVENT_VFORK,
				syscall.PTRACE_EVENT_VFORK_DONE:
				newPid, err := syscall.PtraceGetEventMsg(wpid)
				if err != nil {
					log.Debugf("ptrace.App.collect: PTRACE_EVENT_CLONE/[V]FORK[_DONE] - error getting cloned pid - %v", err)
				} else {
					log.Debugf("ptrace.App.collect: PTRACE_EVENT_CLONE/[V]FORK[_DONE] - cloned pid - %v", newPid)
					if _, ok := pidSyscallState[int(newPid)]; ok {
						log.Debugf("ptrace.App.collect: PTRACE_EVENT_CLONE/[V]FORK[_DONE] - pid already exists - %v", newPid)
						pidSyscallState[int(newPid)].started = true
					} else {
						pidSyscallState[int(newPid)] = &syscallState{pid: int(newPid), started: true}
					}
				}

			case syscall.PTRACE_EVENT_EXEC:
				oldPid, err := syscall.PtraceGetEventMsg(wpid)
				if err != nil {
					log.Debugf("ptrace.App.collect: PTRACE_EVENT_EXEC - error getting old pid - %v", err)
				} else {
					log.Debugf("ptrace.App.collect: PTRACE_EVENT_EXEC - old pid - %v", oldPid)
				}

			case syscall.PTRACE_EVENT_EXIT:
				log.Debugf("ptrace.App.collect: PTRACE_EVENT_EXIT - process exiting pid=%v", wpid)
				if app.MainPID() == wpid {
					mainExiting = true
					log.Debugf("ptrace.App.collect: main process is exiting (%v)", wpid)
				}

				if _, ok := pidSyscallState[wpid]; ok {
					pidSyscallState[wpid].exiting = true
				} else {
					log.Debugf("ptrace.App.collect: unknown process is exiting (%v)", wpid)
				}
			}
		}

		if stopped {
			callSig = statusCode
		}

		doSyscall = true
		callPid = wpid
	}

}

func onSyscall(pid int, cstate *syscallState) error {

	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	cstate.callNum = system.CallNumber(regs)
	cstate.expectReturn = true
	cstate.gotCallNum = true

	// syscall params: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

	// example usage:
	// >> sudo rm -rf dist_linux/.docker-slim-state/ && ./scripts/src.build.quick.sh && ./dist_linux/docker-slim build --target archlinux:latest --http-probe=false --show-clogs --use-local-mounts --cmd "stat -f /etc/hosts" --continue-after 1 2>&1|grep '^!'|grep -e stat -e error
	// ! fstat 3 /etc/ld.so.cache
	// ! fstat 3 /usr/lib/libc-2.32.so
	// ! fstat 3 /usr/lib/locale/locale-archive
	// ! fstat 3 /usr/share/locale/locale.alias
	// ! statfs 10 /etc/hosts
	// ! error: statfs input/output error
	// ! fstat 1 pipe:[2064330]

	name := syscalls[int(cstate.callNum)]
	if name == "fstat" {
		fdpath := fmt.Sprintf("/proc/%d/fd/%d", pid, regs.Rdi)
		path, err := os.Readlink(fdpath)
		if err != nil {
			fmt.Println("err:", err)
		}
		fmt.Println("!", name, regs.Rdi, path)
	} else if name == "stat" || name == "statfs" {
		buffer := make([]byte, 4096)
		_, err := syscall.PtracePeekData(pid, uintptr(regs.Rdi), buffer)
		size := 0
		for i, b := range buffer {
			if b == 0 {
				size = i
				break
			}
		}
		fmt.Println("!", name, size, string(buffer[:size]))
		if err != nil {
			fmt.Println("! error:", name, err)
		}
	} else {
		fmt.Println("!", name)
	}

	return nil
}

func onSyscallReturn(pid int, cstate *syscallState) error {
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	cstate.retVal = system.CallReturnValue(regs)
	cstate.expectReturn = false
	cstate.gotRetVal = true
	return nil
}

///////////////////////////////////

func SignalEnum(sigNum int) string {
	if sigNum >= len(sigEnums) || sigNum < 0 {
		return fmt.Sprintf("BAD(%d)", sigNum)
	}

	e := sigEnums[sigNum]
	if e == "" {
		e = fmt.Sprintf("UNKNOWN(%d)", sigNum)
	}

	return e
}

var sigEnums = [...]string{
	0:                 "(NOSIGNAL)",
	syscall.SIGABRT:   "SIGABRT/SIGIOT",
	syscall.SIGALRM:   "SIGALRM",
	syscall.SIGBUS:    "SIGBUS",
	syscall.SIGCHLD:   "SIGCHLD",
	syscall.SIGCONT:   "SIGCONT",
	syscall.SIGFPE:    "SIGFPE",
	syscall.SIGHUP:    "SIGHUP",
	syscall.SIGILL:    "SIGILL",
	syscall.SIGINT:    "SIGINT",
	syscall.SIGKILL:   "SIGKILL",
	syscall.SIGPIPE:   "SIGPIPE",
	syscall.SIGPOLL:   "SIGIO/SIGPOLL",
	syscall.SIGPROF:   "SIGPROF",
	syscall.SIGPWR:    "SIGPWR",
	syscall.SIGQUIT:   "SIGQUIT",
	syscall.SIGSEGV:   "SIGSEGV",
	syscall.SIGSTKFLT: "SIGSTKFLT",
	syscall.SIGSTOP:   "SIGSTOP",
	syscall.SIGSYS:    "SIGSYS",
	syscall.SIGTERM:   "SIGTERM",
	syscall.SIGTRAP:   "SIGTRAP",
	syscall.SIGTSTP:   "SIGTSTP",
	syscall.SIGTTIN:   "SIGTTIN",
	syscall.SIGTTOU:   "SIGTTOU",
	syscall.SIGURG:    "SIGURG",
	syscall.SIGUSR1:   "SIGUSR1",
	syscall.SIGUSR2:   "SIGUSR2",
	syscall.SIGVTALRM: "SIGVTALRM",
	syscall.SIGWINCH:  "SIGWINCH",
	syscall.SIGXCPU:   "SIGXCPU",
	syscall.SIGXFSZ:   "SIGXFSZ",
}
