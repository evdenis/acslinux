#ifndef _ACSLINUX_
#define _ACSLINUX_ 1

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/key.h>
#include <linux/dcache.h>
#include <linux/fs.h>

struct audit_context;
struct audit_krule;
struct bpf_map;
struct bpf_prog_aux;
struct bpf_prog;
struct cred;
struct dentry;
struct file;
struct flowi;
struct fown_struct;
struct iattr;
struct inode;
struct kern_ipc_perm;
struct key;
struct linux_binprm;
struct mm_struct;
struct msghdr;
struct msg_msg;
struct path;
struct qstr;
struct request_sock;
struct rlimit;
struct sctp_endpoint;
struct security_mnt_opts;
struct sembuf;
struct seq_file;
struct siginfo;
struct sk_buff;
struct sockaddr_in6;
struct sockaddr_in;
struct sockaddr;
struct socket;
struct sock;
struct super_block;
struct task_struct;
struct timespec64;
struct timezone;
struct user_namespace;
struct vfsmount;
struct vm_area_struct;
struct xfrm_policy;
struct xfrm_sec_ctx;
struct xfrm_state;
struct xfrm_user_sec_ctx;

/*@ axiomatic Cred {
    predicate valid_cred(struct cred *c) =
       \valid(c);
    }
 */

/*@ axiomatic TaskStruct {
    predicate valid_task_struct(struct task_struct *t) =
       \valid(t);
    }
 */

/*@ axiomatic FileSystem {
 
    predicate valid_super_block(struct super_block *sb) =
          \valid(sb)
       && valid_dentry(sb->s_root)
       && IS_ROOT(sb->s_root);

    predicate valid_inode(struct inode *i) =
          \valid(i)
       && valid_super_block(i->i_sb);

    predicate valid_dentry(struct dentry *d) =
          \valid(d)
       && \valid(d->d_parent)
       && (!IS_ROOT(d) ==> valid_dentry(d->d_parent))
       && (valid_inode(d->d_inode) || d->d_inode == \null)
       && (valid_super_block(d->d_sb));

    predicate valid_file(struct file *f) =
          \valid(f)
       && (\valid(f->f_inode) || f->f_inode == \null)
       && valid_cred(f->f_cred);

    }
 */

/*@
    predicate valid_linux_binprm(struct linux_binprm *b) = \true;
    predicate valid_user_namespace(struct user_namespace *un) = \true;
    predicate valid_qstr(struct qstr *s) = \true;
    predicate valid_vm_area_struct(struct vm_area_struct *va) = \true;
    predicate valid_fown_struct(struct fown_struct *f) = \true;
    predicate valid_str(char *s) = \true;
    predicate valid_path(struct path *p) = \true;
    predicate valid_iattr(struct iattr *p) = \true;
    predicate valid_kern_ipc_perm(struct kern_ipc_perm *kip) = \true;
    predicate valid_msg_msg(struct msg_msg *mm) = \true;
    predicate valid_security_mnt_opts(struct security_mnt_opts *smo) = \true;
    predicate valid_seq_file(struct seq_file *sf) = \true;
    predicate valid_vfsmount(struct vfsmount *vm) = \true;
    predicate valid_sembuf(struct sembuf *sb) = \true;
    predicate valid_timespec64(struct timespec64 *ts64) = \true;
    predicate valid_timezone(struct timezone *tz) = \true;
    predicate valid_siginfo(struct siginfo *si) = \true;
    predicate valid_rlimit(struct rlimit *rl) = \true;
    predicate valid_mm_struct(struct mm_struct *ms) = \true;
    predicate valid_audit_krule(struct audit_krule *ak) = \true;
    predicate valid_audit_context(struct audit_context *ac) = \true;
    predicate valid_key(struct key *k) = \true;
    predicate valid_request_sock(struct request_sock *rs) = \true;
    predicate valid_flowi(struct flowi *f) = \true;
    predicate valid_sctp_endpoint(struct sctp_endpoint *se) = \true;
    predicate valid_sockaddr(struct sockaddr *sa) = \true;
    predicate valid_sock(struct sock *sk) = \true;
    predicate valid_sk_buff(struct sk_buff *sb) = \true;
    predicate valid_socket(struct socket *s) = \true;
    predicate valid_msghdr(struct msghdr *mh) = \true;
 */

typedef struct seclabel {
} seclabel_t;

#endif
