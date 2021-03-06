#ifndef _ACSLINUX_
#define _ACSLINUX_ 1

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/key.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm_types.h>
#include <net/request_sock.h>
#include <linux/msg.h>
#include <linux/bpf.h>
#include <net/xfrm.h>

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

typedef struct seclabel {
   //TODO add refcnt for secmark
} seclabel_t;

// TODO:
// add implementation for security alloc functions
// add implementation for security free functions
// add implementation for secid functions?
// add specifications for validation of secid?

/*@ axiomatic Cred {
    predicate valid_cred(struct cred *c) =
          \valid(c)
       && \offset_min(c) == 0
       && \typeof(c->security) <: \type(seclabel_t *)
       && (c->security == \null || valid_seclabel((seclabel_t *)c->security))
       && valid_user_namespace(c->user_ns)
       && 0 < c->usage.counter;
    }
 */

/*@ axiomatic TaskStruct {
    predicate valid_task_struct(struct task_struct *t) =
          \valid(t)
       && valid_cred(t->cred)
       && valid_cred(t->real_cred)
       && (t->ptracer_cred == \null || valid_cred(t->ptracer_cred))
       && valid_mm_struct(t->mm)
       && valid_mm_struct(t->active_mm)
       && (t->parent == \null || valid_task_struct(t->parent))
       && (t->real_parent == \null || valid_task_struct(t->real_parent))
#ifdef CONFIG_MMU
       && (t->oom_reaper_list == \null || valid_task_struct(t->oom_reaper_list))
#endif
       && (t->audit_context == \null || valid_audit_context(t->audit_context));
    }
 */

/*@ axiomatic FileSystem {
 
    predicate valid_super_block(struct super_block *sb) =
          \valid(sb)
       && \typeof(sb->s_security) <: \type(seclabel_t *)
       && (sb->s_security == \null || valid_seclabel((seclabel_t *)sb->s_security))
       && valid_dentry(sb->s_root)
       && IS_ROOT(sb->s_root);

    predicate valid_inode(struct inode *i) =
          \valid(i)
       && \typeof(i->i_security) <: \type(seclabel_t *)
       && (i->i_security == \null || valid_seclabel((seclabel_t *)i->i_security))
       && valid_super_block(i->i_sb);

    predicate valid_dentry(struct dentry *d) =
          \valid(d)
       && \valid(d->d_parent)
       && (!IS_ROOT(d) ==> valid_dentry(d->d_parent))
       && (valid_inode(d->d_inode) || d->d_inode == \null)
       && (valid_super_block(d->d_sb));

    predicate valid_file(struct file *f) =
          \valid(f)
       && \typeof(f->f_security) <: \type(seclabel_t *)
       && (f->f_security == \null || valid_seclabel((seclabel_t *)f->f_security))
       && (\valid(f->f_inode) || f->f_inode == \null)
       && valid_cred(f->f_cred);

    }
 */

/*@
    predicate valid_linux_binprm(struct linux_binprm *b) =
          \valid(b)
       //&& valid_mm_struct(b->mm)
       && valid_file(b->file)
       && valid_cred(b->cred)
       && valid_str(b->filename)
       && valid_str(b->interp);
    predicate valid_user_namespace(struct user_namespace *un) =
       \valid(un);
       //&& valid_user_namespace(un->parent);
    predicate valid_qstr(struct qstr *s) =
          \valid(s)
       && valid_str((char *)s->name);
    predicate valid_vm_area_struct(struct vm_area_struct *va) =
          \valid(va);
       //&& valid_mm_struct(va->vm_mm);
    predicate valid_fown_struct(struct fown_struct *f) =
       \valid(f);
    predicate valid_str(char *s) =
       \valid(s); // TODO:
    logic size_t strlen(char *s) = 0; // TODO;
    predicate valid_path(struct path *p) =
          \valid(p)
       && valid_vfsmount(p->mnt)
       && valid_dentry(p->dentry);
    predicate valid_iattr(struct iattr *p) =
          \valid(p)
       && valid_file(p->ia_file);
    predicate valid_kern_ipc_perm(struct kern_ipc_perm *kip) =
       \valid(kip);
    predicate valid_msg_msg(struct msg_msg *mm) =
          \valid(mm)
       && \typeof(mm->security) <: \type(seclabel_t *)
       && (mm->security == \null || valid_seclabel((seclabel_t *)mm->security));
    predicate valid_security_mnt_opts(struct security_mnt_opts *smo) =
          \valid(smo)
       && \valid(smo->mnt_opts)
       && \valid(*(smo->mnt_opts))
       && \valid(smo->mnt_opts_flags);
    predicate valid_seq_file(struct seq_file *sf) =
          \valid(sf)
       && \valid(sf->buf + (0 .. sf->size - 1))
       && valid_file(sf->file);
    predicate valid_vfsmount(struct vfsmount *vm) =
          \valid(vm)
       && valid_dentry(vm->mnt_root)
       && valid_super_block(vm->mnt_sb);
    predicate valid_sembuf(struct sembuf *sb) =
       \valid(sb);
    predicate valid_timespec64(struct timespec64 *ts64) =
       \valid(ts64);
    predicate valid_timespec(struct timespec *ts) =
       \valid(ts);
    predicate valid_timezone(struct timezone *tz) =
       \valid(tz);
    predicate valid_siginfo(struct siginfo *si) =
       \valid(si);
    predicate valid_rlimit(struct rlimit *rl) =
       \valid(rl);
    predicate valid_mm_struct(struct mm_struct *ms) =
          \valid(ms)
       && valid_vm_area_struct(ms->mmap)
#ifdef CONFIG_MEMCG
       && valid_task_struct(ms->owner)
#endif
       && valid_user_namespace(ms->user_ns)
       && valid_file(ms->exe_file);
    predicate valid_audit_krule(struct audit_krule *ak) =
       \valid(ak);
    predicate valid_audit_context(struct audit_context *ac) =
       \valid(ac);
    predicate valid_key(struct key *k) =
       \valid(k);
    predicate valid_request_sock(struct request_sock *rs) =
          \valid(rs)
       && valid_sock(rs->sk);
    predicate valid_flowi(struct flowi *f) =
       \valid(f);
    predicate valid_sctp_endpoint(struct sctp_endpoint *se) =
       \valid(se);
    predicate valid_sockaddr(struct sockaddr *sa) =
       \valid(sa);
    predicate valid_sock(struct sock *sk) =
       \valid(sk);
    predicate valid_sk_buff(struct sk_buff *sb) =
          \valid(sb)
       && valid_sock(sb->sk);
    predicate valid_socket(struct socket *s) =
          \valid(s)
       && valid_sock(s->sk)
       && valid_file(s->file);
    predicate valid_msghdr(struct msghdr *mh) =
          \valid(mh)
       && \typeof(mh->msg_name) <: \type(char *)
       && \valid((char *)mh->msg_name + (0 .. mh->msg_namelen - 1))
       && \typeof(mh->msg_control) <: \type(char *)
       && \valid((char *)mh->msg_control + (0 .. mh->msg_controllen - 1));
    predicate valid_bpf_map(struct bpf_map *bm) =
          \valid(bm)
       && \typeof(bm->security) <: \type(seclabel_t *)
       && (bm->security == \null || valid_seclabel((seclabel_t *)bm->security));
    predicate valid_bpf_prog(struct bpf_prog *bp) =
          \valid(bp)
       && valid_bpf_prog_aux(bp->aux);
    predicate valid_bpf_prog_aux(struct bpf_prog_aux *bpa) =
          \valid(bpa)
       && valid_bpf_prog(bpa->prog)
       && \typeof(bpa->security) <: \type(seclabel_t *)
       && (bpa->security == \null || valid_seclabel((seclabel_t *)bpa->security));
    predicate valid_xfrm_user_sec_ctx(struct xfrm_user_sec_ctx *ctx) =
       \valid(ctx);
    predicate valid_xfrm_sec_ctx(struct xfrm_sec_ctx *ctx) =
       \valid(ctx);
    predicate valid_xfrm_state(struct xfrm_state *st) =
          \valid(st)
       && valid_xfrm_sec_ctx(st->security);
    predicate valid_xfrm_policy(struct xfrm_policy *xp) =
          \valid(xp)
       && valid_xfrm_sec_ctx(xp->security);
 */

/*@ axiomatic SecLabel {
    predicate valid_seclabel(seclabel_t *s) =
          \valid(s)
       && \offset_min(s) == 0;
    }
 */

#endif
