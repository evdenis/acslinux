#ifndef _ACSLINUX_
#define _ACSLINUX_ 1

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
    predicate valid_task(struct task_struct *t) =
       \valid(t);
    }
 */

/*@ axiomatic FS {
 
    predicate valid_super_block(struct super_block *sb) =
          \valid(sb)
       && valid_dentry(sb->s_root)
       && IS_ROOT(sb->s_root);

    predicate valid_inode(struct inode *i) =
          \valid(i)
       && valid_super_block(i->i_sb);

    predicate valid_dentry(struct dentry *d) =
          \valid(d)
       && \valid(d->d_hash)
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

typedef struct seclabel {
} seclabel_t;

#endif
