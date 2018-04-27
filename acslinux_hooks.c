/** @binder_set_context_mgr:
 *	Check whether @mgr is allowed to be the binder context manager.
 *	@mgr contains the task_struct for the task being registered.
 *	Return 0 if permission is granted.
 */
static int acslinux_binder_set_context_mgr(struct task_struct *mgr)
{
	return 0;
}

/** @binder_transaction:
 *	Check whether @from is allowed to invoke a binder transaction call
 *	to @to.
 *	@from contains the task_struct for the sending task.
 *	@to contains the task_struct for the receiving task.
 */
static int acslinux_binder_transaction(struct task_struct *from,
					struct task_struct *to)
{
	return 0;
}

/** @binder_transfer_binder:
 *	Check whether @from is allowed to transfer a binder reference to @to.
 *	@from contains the task_struct for the sending task.
 *	@to contains the task_struct for the receiving task.
 */
static int acslinux_binder_transfer_binder(struct task_struct *from,
					struct task_struct *to)
{
	return 0;
}

/** @binder_transfer_file:
 *	Check whether @from is allowed to transfer @file to @to.
 *	@from contains the task_struct for the sending task.
 *	@file contains the struct file being transferred.
 *	@to contains the task_struct for the receiving task.
 */
static int acslinux_binder_transfer_file(struct task_struct *from,
					struct task_struct *to,
					struct file *file)
{
	return 0;
}

/** @bprm_check_security:
 *	This hook mediates the point when a search for a binary handler will
 *	begin.  It allows a check the @bprm->security value which is set in the
 *	preceding set_creds call.  The primary difference from set_creds is
 *	that the argv list and envp list are reliably available in @bprm.  This
 *	hook may be called multiple times during a single execve; and in each
 *	pass set_creds is called first.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 */
static int acslinux_bprm_check_security(struct linux_binprm *bprm)
{
	return 0;
}

/** @bprm_committed_creds:
 *	Tidy up after the installation of the new security attributes of a
 *	process being transformed by an execve operation.  The new credentials
 *	have, by this point, been set to @current->cred.  @bprm points to the
 *	linux_binprm structure.  This hook is a good place to perform state
 *	changes on the process such as clearing out non-inheritable signal
 *	state.  This is called immediately after commit_creds().
 */
static void acslinux_bprm_committed_creds(struct linux_binprm *bprm)
{
}

/** @bprm_committing_creds:
 *	Prepare to install the new security attributes of a process being
 *	transformed by an execve operation, based on the old credentials
 *	pointed to by @current->cred and the information set in @bprm->cred by
 *	the bprm_set_creds hook.  @bprm points to the linux_binprm structure.
 *	This hook is a good place to perform state changes on the process such
 *	as closing open file descriptors to which access will no longer be
 *	granted when the attributes are changed.  This is called immediately
 *	before commit_creds().
 */
static void acslinux_bprm_committing_creds(struct linux_binprm *bprm)
{
}

/** @bprm_set_creds:
 *	Save security information in the bprm->security field, typically based
 *	on information about the bprm->file, for later use by the apply_creds
 *	hook.  This hook may also optionally check permissions (e.g. for
 *	transitions between security domains).
 *	This hook may be called multiple times during a single execve, e.g. for
 *	interpreters.  The hook can tell whether it has already been called by
 *	checking to see if @bprm->security is non-NULL.  If so, then the hook
 *	may decide either to retain the security information saved earlier or
 *	to replace it.  The hook must set @bprm->secureexec to 1 if a "secure
 *	exec" has happened as a result of this hook call.  The flag is used to
 *	indicate the need for a sanitized execution environment, and is also
 *	passed in the ELF auxiliary table on the initial stack to indicate
 *	whether libc should enable secure mode.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 */
static int acslinux_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
}

/** @capable:
 *	Check whether the @tsk process has the @cap capability in the indicated
 *	credentials.
 *	@cred contains the credentials to use.
 *	@ns contains the user namespace we want the capability in
 *	@cap contains the capability <include/linux/capability.h>.
 *	@audit contains whether to write an audit message or not
 *	Return 0 if the capability is granted for @tsk.
 */
static int acslinux_capable(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit)
{
	return 0;
}

/** @capget:
 *	Get the @effective, @inheritable, and @permitted capability sets for
 *	the @target process.  The hook may also perform permission checking to
 *	determine if the current process is allowed to see the capability sets
 *	of the @target process.
 *	@target contains the task_struct structure for target process.
 *	@effective contains the effective capability set.
 *	@inheritable contains the inheritable capability set.
 *	@permitted contains the permitted capability set.
 *	Return 0 if the capability sets were successfully obtained.
 */
static int acslinux_capget(struct task_struct *target, kernel_cap_t *effective,
			kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

/** @capset:
 *	Set the @effective, @inheritable, and @permitted capability sets for
 *	the current process.
 *	@new contains the new credentials structure for target process.
 *	@old contains the current credentials structure for target process.
 *	@effective contains the effective capability set.
 *	@inheritable contains the inheritable capability set.
 *	@permitted contains the permitted capability set.
 *	Return 0 and update @new if permission is granted.
 */
static int acslinux_capset(struct cred *new, const struct cred *old,
			const kernel_cap_t *effective,
			const kernel_cap_t *inheritable,
			const kernel_cap_t *permitted)
{
	return 0;
}

/** @cred_alloc_blank:
 *	@cred points to the credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Only allocate sufficient memory and attach to @cred such that
 *	cred_transfer() will not get ENOMEM.
 */
static int acslinux_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

/** @cred_free:
 *	@cred points to the credentials.
 *	Deallocate and clear the cred->security field in a set of credentials.
 */
static void acslinux_cred_free(struct cred *cred)
{
}

/** @cred_getsecid:
 *	Retrieve the security identifier of the cred structure @c
 *	@c contains the credentials, secid will be placed into @secid.
 *	In case of failure, @secid will be set to zero.
 */
static void acslinux_cred_getsecid(const struct cred *c, u32 *secid)
{
}

/** @cred_prepare:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Prepare a new set of credentials by copying the data from the old set.
 */
static int acslinux_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	return 0;
}

/** @cred_transfer:
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	Transfer data from original creds to new creds
 */
static void acslinux_cred_transfer(struct cred *new, const struct cred *old)
{
}

static void acslinux_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

/** @dentry_create_files_as:
 *	Compute a context for a dentry as the inode is not yet available
 *	and set that context in passed in creds so that new files are
 *	created using that context. Context is calculated using the
 *	passed in creds and not the creds of the caller.
 *	@dentry dentry to use in calculating the context.
 *	@mode mode used to determine resource type.
 *	@name name of the last path component used to create file
 *	@old creds which should be used for context calculation
 *	@new creds to modify
 */
static int acslinux_dentry_create_files_as(struct dentry *dentry, int mode,
					struct qstr *name,
					const struct cred *old,
					struct cred *new)
{
	return 0;
}

/** @dentry_init_security:
 *	Compute a context for a dentry as the inode is not yet available
 *	since NFSv4 has no label backed by an EA anyway.
 *	@dentry dentry to use in calculating the context.
 *	@mode mode used to determine resource type.
 *	@name name of the last path component used to create file
 *	@ctx pointer to place the pointer to the resulting context in.
 *	@ctxlen point to place the length of the resulting context.
 */
static int acslinux_dentry_init_security(struct dentry *dentry, int mode,
					const struct qstr *name, void **ctx,
					u32 *ctxlen)
{
	return 0;
}

/** @file_alloc_security:
 *	Allocate and attach a security structure to the file->f_security field.
 *	The security field is initialized to NULL when the structure is first
 *	created.
 *	@file contains the file structure to secure.
 *	Return 0 if the hook is successful and permission is granted.
 */
static int acslinux_file_alloc_security(struct file *file)
{
	return 0;
}

/** @file_fcntl:
 *	Check permission before allowing the file operation specified by @cmd
 *	from being performed on the file @file.  Note that @arg sometimes
 *	represents a user space pointer; in other cases, it may be a simple
 *	integer value.  When @arg represents a user space pointer, it should
 *	never be used by the security module.
 *	@file contains the file structure.
 *	@cmd contains the operation to be performed.
 *	@arg contains the operational arguments.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_fcntl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	return 0;
}

/** @file_free_security:
 *	Deallocate and free any security structures stored in file->f_security.
 *	@file contains the file structure being modified.
 */
static void acslinux_file_free_security(struct file *file)
{
}

/** @file_ioctl:
 *	@file contains the file structure.
 *	@cmd contains the operation to perform.
 *	@arg contains the operational arguments.
 *	Check permission for an ioctl operation on @file.  Note that @arg
 *	sometimes represents a user space pointer; in other cases, it may be a
 *	simple integer value.  When @arg represents a user space pointer, it
 *	should never be used by the security module.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	return 0;
}

/** @file_lock:
 *	Check permission before performing file locking operations.
 *	Note: this hook mediates both flock and fcntl style locks.
 *	@file contains the file structure.
 *	@cmd contains the posix-translated lock operation to perform
 *	(e.g. F_RDLCK, F_WRLCK).
 *	Return 0 if permission is granted.
 */
static int acslinux_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

/** @file_mprotect:
 *	Check permissions before changing memory access permissions.
 *	@vma contains the memory region to modify.
 *	@reqprot contains the protection requested by the application.
 *	@prot contains the protection that will be applied by the kernel.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
				unsigned long prot)
{
	return 0;
}

/** @file_open:
 *	Save open-time permission checking state for later use upon
 *	file_permission, and recheck access if anything has changed
 *	since inode_permission.
 */
static int acslinux_file_open(struct file *file, const struct cred *cred)
{
	return 0;
}

/** @file_permission:
 *	Check file permissions before accessing an open file.  This hook is
 *	called by various operations that read or write files.  A security
 *	module can use this hook to perform additional checking on these
 *	operations, e.g.  to revalidate permissions on use to support privilege
 *	bracketing or policy changes.  Notice that this hook is used when the
 *	actual read/write operations are performed, whereas the
 *	inode_security_ops hook is called when a file is opened (as well as
 *	many other operations).
 *	Caveat:  Although this hook can be used to revalidate permissions for
 *	various system call operations that read or write files, it does not
 *	address the revalidation of permissions for memory-mapped files.
 *	Security modules must handle this separately if they need such
 *	revalidation.
 *	@file contains the file structure being accessed.
 *	@mask contains the requested permissions.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_permission(struct file *file, int mask)
{
	return 0;
}

/** @file_receive:
 *	This hook allows security modules to control the ability of a process
 *	to receive an open file descriptor via socket IPC.
 *	@file contains the file structure being received.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_receive(struct file *file)
{
	return 0;
}

/** @file_send_sigiotask:
 *	Check permission for the file owner @fown to send SIGIO or SIGURG to the
 *	process @tsk.  Note that this hook is sometimes called from interrupt.
 *	Note that the fown_struct, @fown, is never outside the context of a
 *	struct file, so the file structure (and associated security information)
 *	can always be obtained: container_of(fown, struct file, f_owner)
 *	@tsk contains the structure of task receiving signal.
 *	@fown contains the file owner information.
 *	@sig is the signal that will be sent.  When 0, kernel sends SIGIO.
 *	Return 0 if permission is granted.
 */
static int acslinux_file_send_sigiotask(struct task_struct *tsk,
					struct fown_struct *fown, int sig)
{
	return 0;
}

/** @file_set_fowner:
 *	Save owner security information (typically from current->security) in
 *	file->f_security for later use by the send_sigiotask hook.
 *	@file contains the file structure to update.
 *	Return 0 on success.
 */
static void acslinux_file_set_fowner(struct file *file)
{
}

static int acslinux_getprocattr(struct task_struct *p, char *name, char **value)
{
	return 0;
}

/** @inode_alloc_security:
 *	Allocate and attach a security structure to @inode->i_security.  The
 *	i_security field is initialized to NULL when the inode structure is
 *	allocated.
 *	@inode contains the inode structure.
 *	Return 0 if operation was successful.
 */
static int acslinux_inode_alloc_security(struct inode *inode)
{
	return 0;
}

/** @inode_copy_up:
 *	A file is about to be copied up from lower layer to upper layer of
 *	overlay filesystem. Security module can prepare a set of new creds
 *	and modify as need be and return new creds. Caller will switch to
 *	new creds temporarily to create new file and release newly allocated
 *	creds.
 *	@src indicates the union dentry of file that is being copied up.
 *	@new pointer to pointer to return newly allocated creds.
 *	Returns 0 on success or a negative error code on error.
 */
static int acslinux_inode_copy_up(struct dentry *src, struct cred **new)
{
	return 0;
}

/** @inode_copy_up_xattr:
 *	Filter the xattrs being copied up when a unioned file is copied
 *	up from a lower layer to the union/overlay layer.
 *	@name indicates the name of the xattr.
 *	Returns 0 to accept the xattr, 1 to discard the xattr, -EOPNOTSUPP if
 *	security module does not know about attribute or a negative error code
 *	to abort the copy up. Note that the caller is responsible for reading
 *	and writing the xattrs as this hook is merely a filter.
 */
static int acslinux_inode_copy_up_xattr(const char *name)
{
	return 0;
}

/** @inode_create:
 *	Check permission to create a regular file.
 *	@dir contains inode structure of the parent of the new file.
 *	@dentry contains the dentry structure for the file to be created.
 *	@mode contains the file mode of the file to be created.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_create(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	return 0;
}

/** @inode_follow_link:
 *	Check permission to follow a symbolic link when looking up a pathname.
 *	@dentry contains the dentry structure for the link.
 *	@inode contains the inode, which itself is not stable in RCU-walk
 *	@rcu indicates whether we are in RCU-walk mode.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_follow_link(struct dentry *dentry, struct inode *inode,
				 bool rcu)
{
	return 0;
}

/** @inode_free_security:
 *	@inode contains the inode structure.
 *	Deallocate the inode security structure and set @inode->i_security to
 *	NULL.
 */
static void acslinux_inode_free_security(struct inode *inode)
{
}

/** @inode_getattr:
 *	Check permission before obtaining file attributes.
 *	@path contains the path structure for the file.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_getattr(const struct path *path)
{
	return 0;
}

/** @inode_getsecctx:
 *	On success, returns 0 and fills out @ctx and @ctxlen with the security
 *	context for the given @inode.
 */
static int acslinux_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return 0;
}

/** @inode_getsecid:
 *	Get the secid associated with the node.
 *	@inode contains a pointer to the inode.
 *	@secid contains a pointer to the location where result will be saved.
 *	In case of failure, @secid will be set to zero.
 */
static void acslinux_inode_getsecid(struct inode *inode, u32 *secid)
{
}

/** @inode_getsecurity:
 *	Retrieve a copy of the extended attribute representation of the
 *	security label associated with @name for @inode via @buffer.  Note that
 *	@name is the remainder of the attribute name after the security prefix
 *	has been removed. @alloc is used to specify of the call should return a
 *	value via the buffer or just the value length Return size of buffer on
 *	success.
 */
static int acslinux_inode_getsecurity(struct inode *inode, const char *name,
					void **buffer, bool alloc)
{
	return 0;
}

/** @inode_getxattr:
 *	Check permission before obtaining the extended attributes
 *	identified by @name for @dentry.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

/** @inode_init_security:
 *	Obtain the security attribute name suffix and value to set on a newly
 *	created inode and set up the incore security field for the new inode.
 *	This hook is called by the fs code as part of the inode creation
 *	transaction and provides for atomic labeling of the inode, unlike
 *	the post_create/mkdir/... hooks called by the VFS.  The hook function
 *	is expected to allocate the name and value via kmalloc, with the caller
 *	being responsible for calling kfree after using them.
 *	If the security module does not use security attributes or does
 *	not wish to put a security attribute on this particular inode,
 *	then it should return -EOPNOTSUPP to skip this processing.
 *	@inode contains the inode structure of the newly created inode.
 *	@dir contains the inode structure of the parent directory.
 *	@qstr contains the last path component of the new object
 *	@name will be set to the allocated name suffix (e.g. selinux).
 *	@value will be set to the allocated attribute value.
 *	@len will be set to the length of the value.
 *	Returns 0 if @name and @value have been successfully set,
 *	-EOPNOTSUPP if no security attribute is needed, or
 *	-ENOMEM on memory allocation failure.
 */
static int acslinux_inode_init_security(struct inode *inode, struct inode *dir,
					const struct qstr *qstr,
					const char **name, void **value,
					size_t *len)
{
	return 0;
}

/** @inode_invalidate_secctx:
 *	Notify the security module that it must revalidate the security context
 *	of an inode.
 */
static void acslinux_inode_invalidate_secctx(struct inode *inode)
{
}

/** @inode_killpriv:
 *	The setuid bit is being removed.  Remove similar security labels.
 *	Called with the dentry->d_inode->i_mutex held.
 *	@dentry is the dentry being changed.
 *	Return 0 on success.  If error is returned, then the operation
 *	causing setuid bit removal is failed.
 */
static int acslinux_inode_killpriv(struct dentry *dentry)
{
	return 0;
}

/** @inode_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing
 *	link to the file.
 *	@dir contains the inode structure of the parent directory
 *	of the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_link(struct dentry *old_dentry, struct inode *dir,
				struct dentry *new_dentry)
{
	return 0;
}

/** @inode_listsecurity:
 *	Copy the extended attribute names for the security labels
 *	associated with @inode into @buffer.  The maximum size of @buffer
 *	is specified by @buffer_size.  @buffer may be NULL to request
 *	the size of the buffer required.
 *	Returns number of bytes used/required on success.
 */
static int acslinux_inode_listsecurity(struct inode *inode, char *buffer,
					size_t buffer_size)
{
	return 0;
}

/** @inode_listxattr:
 *	Check permission before obtaining the list of extended attribute
 *	names for @dentry.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

/** @inode_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with inode structure @dir.
 *	@dir contains the inode structure of parent of the directory
 *	to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_mkdir(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	return 0;
}

/** @inode_mknod:
 *	Check permissions when creating a special file (or a socket or a fifo
 *	file created via the mknod system call).  Note that if mknod operation
 *	is being done for a regular file, then the create hook will be called
 *	and not this hook.
 *	@dir contains the inode structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the device number.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	return 0;
}

/** @inode_need_killpriv:
 *	Called when an inode has been changed.
 *	@dentry is the dentry being changed.
 *	Return <0 on error to abort the inode change operation.
 *	Return 0 if inode_killpriv does not need to be called.
 *	Return >0 if inode_killpriv does need to be called.
 */
static int acslinux_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}

/** @inode_notifysecctx:
 *	Notify the security module of what the security context of an inode
 *	should be.  Initializes the incore security context managed by the
 *	security module for this inode.  Example usage:  NFS client invokes
 *	this hook to initialize the security context in its incore inode to the
 *	value provided by the server for the file when the server returned the
 *	file's attributes to the client.
 */
static int acslinux_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return 0;
}

/** @inode_permission:
 *	Check permission before accessing an inode.  This hook is called by the
 *	existing Linux permission function, so a security module can use it to
 *	provide additional checking for existing Linux permission checks.
 *	Notice that this hook is called when a file is opened (as well as many
 *	other operations), whereas the file_security_ops permission hook is
 *	called when the actual read/write operations are performed.
 *	@inode contains the inode structure to check.
 *	@mask contains the permission mask.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

/** @inode_post_setxattr:
 *	Update inode security field after successful setxattr operation.
 *	@value identified by @name for @dentry.
 */
static void acslinux_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
}

/** @inode_readlink:
 *	Check the permission to read the symbolic link.
 *	@dentry contains the dentry structure for the file link.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_readlink(struct dentry *dentry)
{
	return 0;
}

/** @inode_removexattr:
 *	Check permission before removing the extended attribute
 *	identified by @name for @dentry.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_removexattr(struct dentry *dentry, const char *name)
{
	return 0;
}

/** @inode_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the inode structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the inode structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	return 0;
}

/** @inode_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the inode structure of parent of the directory
 *	to be removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

/** @inode_setattr:
 *	Check permission before setting file attributes.  Note that the kernel
 *	call to notify_change is performed from several locations, whenever
 *	file attributes change (such as when a file is truncated, chown/chmod
 *	operations, transferring disk quotas, etc).
 *	@dentry contains the dentry structure for the file.
 *	@attr is the iattr structure containing the new file attributes.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	return 0;
}

/** @inode_setsecctx:
 *	Change the security context of an inode.  Updates the
 *	incore security context managed by the security module and invokes the
 *	fs code as needed (via __vfs_setxattr_noperm) to update any backing
 *	xattrs that represent the context.  Example usage:  NFS server invokes
 *	this hook to change the security context in its incore inode and on the
 *	backing filesystem to a value provided by the client on a SETATTR
 *	operation.
 */
static int acslinux_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return 0;
}

/** @inode_setsecurity:
 *	Set the security label associated with @name for @inode from the
 *	extended attribute value @value.  @size indicates the size of the
 *	@value in bytes.  @flags may be XATTR_CREATE, XATTR_REPLACE, or 0.
 *	Note that @name is the remainder of the attribute name after the
 *	security. prefix has been removed.
 *	Return 0 on success.
 */
static int acslinux_inode_setsecurity(struct inode *inode, const char *name,
					const void *value, size_t size,
					int flags)
{
	return 0;
}

/** @inode_setxattr:
 *	Check permission before setting the extended attributes
 *	@value identified by @name for @dentry.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	return 0;
}

/** @inode_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the inode structure of parent directory of
 *	the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_symlink(struct inode *dir, struct dentry *dentry,
				const char *old_name)
{
	return 0;
}

/** @inode_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the inode structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 */
static int acslinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return 0;
}

/** @ipc_getsecid:
 *	Get the secid associated with the ipc object.
 *	@ipcp contains the kernel IPC permission structure.
 *	@secid contains a pointer to the location where result will be saved.
 *	In case of failure, @secid will be set to zero.
 */
static void acslinux_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
}

/** @ipc_permission:
 *	Check permissions for access to IPC
 *	@ipcp contains the kernel IPC permission structure
 *	@flag contains the desired (requested) permission set
 *	Return 0 if permission is granted.
 */
static int acslinux_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

/** @ismaclabel:
 *	Check if the extended attribute specified by @name
 *	represents a MAC label. Returns 1 if name is a MAC
 *	attribute otherwise returns 0.
 *	@name full extended attribute name to check against
 *	LSM as a MAC label.
 */
static int acslinux_ismaclabel(const char *name)
{
	return 0;
}

/** @kernel_act_as:
 *	Set the credentials for a kernel service to act as (subjective context).
 *	@new points to the credentials to be modified.
 *	@secid specifies the security ID to be set
 *	The current task must be the one that nominated @secid.
 *	Return 0 if successful.
 */
static int acslinux_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

/** @kernel_create_files_as:
 *	Set the file creation context in a set of credentials to be the same as
 *	the objective context of the specified inode.
 *	@new points to the credentials to be modified.
 *	@inode points to the inode to use as a reference.
 *	The current task must be the one that nominated @inode.
 *	Return 0 if successful.
 */
static int acslinux_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

/** @kernel_module_request:
 *	Ability to trigger the kernel to automatically upcall to userspace for
 *	userspace to load a kernel module with the given name.
 *	@kmod_name name of the module requested by the kernel
 *	Return 0 if successful.
 */
static int acslinux_kernel_module_request(char *kmod_name)
{
	return 0;
}

/** @kernel_post_read_file:
 *	Read a file specified by userspace.
 *	@file contains the file structure pointing to the file being read
 *	by the kernel.
 *	@buf pointer to buffer containing the file contents.
 *	@size length of the file contents.
 *	@id kernel read file identifier
 *	Return 0 if permission is granted.
 */
static int acslinux_kernel_post_read_file(struct file *file, char *buf, loff_t size,
				     enum kernel_read_file_id id)
{
	return 0;
}

/** @kernel_read_file:
 *	Read a file specified by userspace.
 *	@file contains the file structure pointing to the file being read
 *	by the kernel.
 *	@id kernel read file identifier
 *	Return 0 if permission is granted.
 */
static int acslinux_kernel_read_file(struct file *file, enum kernel_read_file_id id)
{
	return 0;
}

static int acslinux_mmap_addr(unsigned long addr)
{
	return 0;
}

static int acslinux_mmap_file(struct file *file, unsigned long reqprot,
				unsigned long prot, unsigned long flags)
{
	return 0;
}

/** @msg_msg_alloc_security:
 *	Allocate and attach a security structure to the msg->security field.
 *	The security field is initialized to NULL when the structure is first
 *	created.
 *	@msg contains the message structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 */
static int acslinux_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

/** @msg_msg_free_security:
 *	Deallocate the security structure for this message.
 *	@msg contains the message structure to be modified.
 */
static void acslinux_msg_msg_free_security(struct msg_msg *msg)
{
}

/** @msg_queue_alloc_security:
 *	Allocate and attach a security structure to the
 *	msq->q_perm.security field. The security field is initialized to
 *	NULL when the structure is first created.
 *	@msq contains the message queue structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 */
static int acslinux_msg_queue_alloc_security(struct kern_ipc_perm *msq)
{
	return 0;
}

/** @msg_queue_associate:
 *	Check permission when a message queue is requested through the
 *	msgget system call.  This hook is only called when returning the
 *	message queue identifier for an existing message queue, not when a
 *	new message queue is created.
 *	@msq contains the message queue to act upon.
 *	@msqflg contains the operation control flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_msg_queue_associate(struct kern_ipc_perm *msq, int msqflg)
{
	return 0;
}

/** @msg_queue_free_security:
 *	Deallocate security structure for this message queue.
 *	@msq contains the message queue structure to be modified.
 */
static void acslinux_msg_queue_free_security(struct kern_ipc_perm *msq)
{
}

/** @msg_queue_msgctl:
 *	Check permission when a message control operation specified by @cmd
 *	is to be performed on the message queue @msq.
 *	The @msq may be NULL, e.g. for IPC_INFO or MSG_INFO.
 *	@msq contains the message queue to act upon.  May be NULL.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 */
static int acslinux_msg_queue_msgctl(struct kern_ipc_perm *msq, int cmd)
{
	return 0;
}

/** @msg_queue_msgrcv:
 *	Check permission before a message, @msg, is removed from the message
 *	queue, @msq.  The @target task structure contains a pointer to the
 *	process that will be receiving the message (not equal to the current
 *	process when inline receives are being performed).
 *	@msq contains the message queue to retrieve message from.
 *	@msg contains the message destination.
 *	@target contains the task structure for recipient process.
 *	@type contains the type of message requested.
 *	@mode contains the operational flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_msg_queue_msgrcv(struct kern_ipc_perm *msq, struct msg_msg *msg,
				struct task_struct *target, long type,
				int mode)
{
	return 0;
}

/** @msg_queue_msgsnd:
 *	Check permission before a message, @msg, is enqueued on the message
 *	queue, @msq.
 *	@msq contains the message queue to send message to.
 *	@msg contains the message to be enqueued.
 *	@msqflg contains operational flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_msg_queue_msgsnd(struct kern_ipc_perm *msq, struct msg_msg *msg,
				int msqflg)
{
	return 0;
}

/** @netlink_send:
 *	Save security information for a netlink message so that permission
 *	checking can be performed when the message is processed.  The security
 *	information can be saved using the eff_cap field of the
 *	netlink_skb_parms structure.  Also may be used to provide fine
 *	grained control over message transmission.
 *	@sk associated sock of task sending the message.
 *	@skb contains the sk_buff structure for the netlink message.
 *	Return 0 if the information was successfully saved and message
 *	is allowed to be transmitted.
 */
static int acslinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

/** @ptrace_access_check:
 *	Check permission before allowing the current process to trace the
 *	@child process.
 *	Security modules may also want to perform a process tracing check
 *	during an execve in the set_security or apply_creds hooks of
 *	tracing check during an execve in the bprm_set_creds hook of
 *	binprm_security_ops if the process is being traced and its security
 *	attributes would be changed by the execve.
 *	@child contains the task_struct structure for the target process.
 *	@mode contains the PTRACE_MODE flags indicating the form of access.
 *	Return 0 if permission is granted.
 */
static int acslinux_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	return 0;
}

/** @ptrace_traceme:
 *	Check that the @parent process has sufficient permission to trace the
 *	current process before allowing the current process to present itself
 *	to the @parent process for tracing.
 *	@parent contains the task_struct structure for debugger process.
 *	Return 0 if permission is granted.
 */
static int acslinux_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int acslinux_quota_on(struct dentry *dentry)
{
	return 0;
}

static int acslinux_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

/** @release_secctx:
 *	Release the security context.
 *	@secdata contains the security context.
 *	@seclen contains the length of the security context.
 */
static void acslinux_release_secctx(char *secdata, u32 seclen)
{
}

/** @sb_alloc_security:
 *	Allocate and attach a security structure to the sb->s_security field.
 *	The s_security field is initialized to NULL when the structure is
 *	allocated.
 *	@sb contains the super_block structure to be modified.
 *	Return 0 if operation was successful.
 */
static int acslinux_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

/** @sb_clone_mnt_opts:
 *	Copy all security options from a given superblock to another
 *	@oldsb old superblock which contain information to clone
 *	@newsb new superblock which needs filled in
 */
static int acslinux_sb_clone_mnt_opts(const struct super_block *oldsb,
					struct super_block *newsb,
					unsigned long kern_flags,
					unsigned long *set_kern_flags)
{
	return 0;
}

/** @sb_copy_data:
 *	Allow mount option data to be copied prior to parsing by the filesystem,
 *	so that the security module can extract security-specific mount
 *	options cleanly (a filesystem may modify the data e.g. with strsep()).
 *	This also allows the original mount data to be stripped of security-
 *	specific options to avoid having to make filesystems aware of them.
 *	@type the type of filesystem being mounted.
 *	@orig the original mount data copied from userspace.
 *	@copy copied data which will be passed to the security module.
 *	Returns 0 if the copy was successful.
 */
static int acslinux_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

/** @sb_free_security:
 *	Deallocate and clear the sb->s_security field.
 *	@sb contains the super_block structure to be modified.
 */
static void acslinux_sb_free_security(struct super_block *sb)
{
}

static int acslinux_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

/** @sb_mount:
 *	Check permission before an object specified by @dev_name is mounted on
 *	the mount point named by @nd.  For an ordinary mount, @dev_name
 *	identifies a device if the file system type requires a device.  For a
 *	remount (@flags & MS_REMOUNT), @dev_name is irrelevant.  For a
 *	loopback/bind mount (@flags & MS_BIND), @dev_name identifies the
 *	pathname of the object being mounted.
 *	@dev_name contains the name for object being mounted.
 *	@path contains the path for mount point object.
 *	@type contains the filesystem type.
 *	@flags contains the mount flags.
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 */
static int acslinux_sb_mount(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data)
{
	return 0;
}

/** @sb_parse_opts_str:
 *	Parse a string of security data filling in the opts structure
 *	@options string containing all mount options known by the LSM
 *	@opts binary data structure usable by the LSM
 */
static int acslinux_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return 0;
}

/** @sb_pivotroot:
 *	Check permission before pivoting the root filesystem.
 *	@old_path contains the path for the new location of the
 *	current root (put_old).
 *	@new_path contains the path for the new root (new_root).
 *	Return 0 if permission is granted.
 */
static int acslinux_sb_pivotroot(const struct path *old_path, const struct path *new_path)
{
	return 0;
}

/** @sb_remount:
 *	Extracts security system specific mount options and verifies no changes
 *	are being made to those options.
 *	@sb superblock being remounted
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 */
static int acslinux_sb_remount(struct super_block *sb, void *data)
{
	return 0;
}

/** @sb_set_mnt_opts:
 *	Set the security relevant mount options used for a superblock
 *	@sb the superblock to set security mount options for
 *	@opts binary data structure containing all lsm mount data
 */
static int acslinux_sb_set_mnt_opts(struct super_block *sb,
				struct security_mnt_opts *opts,
				unsigned long kern_flags,
				unsigned long *set_kern_flags)
{
	return 0;
}

static int acslinux_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

/** @sb_statfs:
 *	Check permission before obtaining filesystem statistics for the @mnt
 *	mountpoint.
 *	@dentry is a handle on the superblock for the filesystem.
 *	Return 0 if permission is granted.
 */
static int acslinux_sb_statfs(struct dentry *dentry)
{
	return 0;
}

/** @sb_umount:
 *	Check permission before the @mnt file system is unmounted.
 *	@mnt contains the mounted file system.
 *	@flags contains the unmount flags, e.g. MNT_FORCE.
 *	Return 0 if permission is granted.
 */
static int acslinux_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

/** @secctx_to_secid:
 *	Convert security context to secid.
 *	@secid contains the pointer to the generated security ID.
 *	@secdata contains the security context.
 */
static int acslinux_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return 0;
}

/** @secid_to_secctx:
 *	Convert secid to security context.  If secdata is NULL the length of
 *	the result will be returned in seclen, but no secdata will be returned.
 *	This does mean that the length could change between calls to check the
 *	length and the next call which actually allocates and returns the
 *	secdata.
 *	@secid contains the security ID.
 *	@secdata contains the pointer that stores the converted security
 *	context.
 *	@seclen pointer which contains the length of the data
 */
static int acslinux_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return 0;
}

/** @sem_alloc_security:
 *	Allocate and attach a security structure to the sma->sem_perm.security
 *	field.  The security field is initialized to NULL when the structure is
 *	first created.
 *	@sma contains the semaphore structure
 *	Return 0 if operation was successful and permission is granted.
 */
static int acslinux_sem_alloc_security(struct kern_ipc_perm *sma)
{
	return 0;
}

/** @sem_associate:
 *	Check permission when a semaphore is requested through the semget
 *	system call.  This hook is only called when returning the semaphore
 *	identifier for an existing semaphore, not when a new one must be
 *	created.
 *	@sma contains the semaphore structure.
 *	@semflg contains the operation control flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_sem_associate(struct kern_ipc_perm *sma, int semflg)
{
	return 0;
}

/** @sem_free_security:
 *	deallocate security struct for this semaphore
 *	@sma contains the semaphore structure.
 */
static void acslinux_sem_free_security(struct kern_ipc_perm *sma)
{
}

/** @sem_semctl:
 *	Check permission when a semaphore operation specified by @cmd is to be
 *	performed on the semaphore @sma.  The @sma may be NULL, e.g. for
 *	IPC_INFO or SEM_INFO.
 *	@sma contains the semaphore structure.  May be NULL.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 */
static int acslinux_sem_semctl(struct kern_ipc_perm *sma, int cmd)
{
	return 0;
}

/** @sem_semop:
 *	Check permissions before performing operations on members of the
 *	semaphore set @sma.  If the @alter flag is nonzero, the semaphore set
 *	may be modified.
 *	@sma contains the semaphore structure.
 *	@sops contains the operations to perform.
 *	@nsops contains the number of operations to perform.
 *	@alter contains the flag indicating whether changes are to be made.
 *	Return 0 if permission is granted.
 */
static int acslinux_sem_semop(struct kern_ipc_perm *sma, struct sembuf *sops,
				unsigned nsops, int alter)
{
	return 0;
}

static int acslinux_setprocattr(const char *name, void *value, size_t size)
{
	return 0;
}

/** @settime:
 *	Check permission to change the system time.
 *	struct timespec64 is defined in include/linux/time64.h and timezone
 *	is defined in include/linux/time.h
 *	@ts contains new time
 *	@tz contains new timezone
 *	Return 0 if permission is granted.
 */
static int acslinux_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	return 0;
}

/** @shm_alloc_security:
 *	Allocate and attach a security structure to the shp->shm_perm.security
 *	field.  The security field is initialized to NULL when the structure is
 *	first created.
 *	@shp contains the shared memory structure to be modified.
 *	Return 0 if operation was successful and permission is granted.
 */
static int acslinux_shm_alloc_security(struct kern_ipc_perm *shp)
{
	return 0;
}

/** @shm_associate:
 *	Check permission when a shared memory region is requested through the
 *	shmget system call.  This hook is only called when returning the shared
 *	memory region identifier for an existing region, not when a new shared
 *	memory region is created.
 *	@shp contains the shared memory structure to be modified.
 *	@shmflg contains the operation control flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_shm_associate(struct kern_ipc_perm *shp, int shmflg)
{
	return 0;
}

/** @shm_free_security:
 *	Deallocate the security struct for this memory segment.
 *	@shp contains the shared memory structure to be modified.
 */
static void acslinux_shm_free_security(struct kern_ipc_perm *shp)
{
}

/** @shm_shmat:
 *	Check permissions prior to allowing the shmat system call to attach the
 *	shared memory segment @shp to the data segment of the calling process.
 *	The attaching address is specified by @shmaddr.
 *	@shp contains the shared memory structure to be modified.
 *	@shmaddr contains the address to attach memory region to.
 *	@shmflg contains the operational flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_shm_shmat(struct kern_ipc_perm *shp, char __user *shmaddr,
				int shmflg)
{
	return 0;
}

/** @shm_shmctl:
 *	Check permission when a shared memory control operation specified by
 *	@cmd is to be performed on the shared memory region @shp.
 *	The @shp may be NULL, e.g. for IPC_INFO or SHM_INFO.
 *	@shp contains shared memory structure to be modified.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 */
static int acslinux_shm_shmctl(struct kern_ipc_perm *shp, int cmd)
{
	return 0;
}

/** @syslog:
 *	Check permission before accessing the kernel message ring or changing
 *	logging to the console.
 *	See the syslog(2) manual page for an explanation of the @type values.
 *	@type contains the type of action.
 *	@from_file indicates the context of action (if it came from /proc).
 *	Return 0 if permission is granted.
 */
static int acslinux_syslog(int type)
{
	return 0;
}

/** @task_alloc:
 *	@task task being allocated.
 *	@clone_flags contains the flags indicating what should be shared.
 *	Handle allocation of task-related resources.
 *	Returns a zero on success, negative values on failure.
 */
static int acslinux_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	return 0;
}

/** @task_fix_setuid:
 *	Update the module's state after setting one or more of the user
 *	identity attributes of the current process.  The @flags parameter
 *	indicates which of the set*uid system calls invoked this hook.  If
 *	@new is the set of credentials that will be installed.  Modifications
 *	should be made to this rather than to @current->cred.
 *	@old is the set of credentials that are being replaces
 *	@flags contains one of the LSM_SETID_* values.
 *	Return 0 on success.
 */
static int acslinux_task_fix_setuid(struct cred *new, const struct cred *old,
				int flags)
{
	return 0;
}

/** @task_free:
 *	@task task about to be freed.
 *	Handle release of task-related resources. (Note that this can be called
 *	from interrupt context.)
 */
static void acslinux_task_free(struct task_struct *task)
{
}

static int acslinux_task_getioprio(struct task_struct *p)
{
	return 0;
}

/** @task_getpgid:
 *	Check permission before getting the process group identifier of the
 *	process @p.
 *	@p contains the task_struct for the process.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_getpgid(struct task_struct *p)
{
	return 0;
}

/** @task_getscheduler:
 *	Check permission before obtaining scheduling information for process
 *	@p.
 *	@p contains the task_struct for process.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_getscheduler(struct task_struct *p)
{
	return 0;
}

/** @task_getsecid:
 *	Retrieve the security identifier of the process @p.
 *	@p contains the task_struct for the process and place is into @secid.
 *	In case of failure, @secid will be set to zero.
 */
static void acslinux_task_getsecid(struct task_struct *p, u32 *secid)
{
}

/** @task_getsid:
 *	Check permission before getting the session identifier of the process
 *	@p.
 *	@p contains the task_struct for the process.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_getsid(struct task_struct *p)
{
	return 0;
}

/** @task_kill:
 *	Check permission before sending signal @sig to @p.  @info can be NULL,
 *	the constant 1, or a pointer to a siginfo structure.  If @info is 1 or
 *	SI_FROMKERNEL(info) is true, then the signal should be viewed as coming
 *	from the kernel and should typically be permitted.
 *	SIGIO signals are handled separately by the send_sigiotask hook in
 *	file_security_ops.
 *	@p contains the task_struct for process.
 *	@info contains the signal information.
 *	@sig contains the signal value.
 *	@cred contains the cred of the process where the signal originated, or
 *	NULL if the current task is the originator.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_kill(struct task_struct *p, struct siginfo *info,
				int sig, const struct cred *cred)
{
	return 0;
}

static int acslinux_task_movememory(struct task_struct *p)
{
	return 0;
}

/** @task_prctl:
 *	Check permission before performing a process control operation on the
 *	current process.
 *	@option contains the operation.
 *	@arg2 contains a argument.
 *	@arg3 contains a argument.
 *	@arg4 contains a argument.
 *	@arg5 contains a argument.
 *	Return -ENOSYS if no-one wanted to handle this op, any other value to
 *	cause prctl() to return immediately with that value.
 */
static int acslinux_task_prctl(int option, unsigned long arg2, unsigned long arg3,
				unsigned long arg4, unsigned long arg5)
{
	return 0;
}

/** @task_prlimit:
 *	Check permission before getting and/or setting the resource limits of
 *	another task.
 *	@cred points to the cred structure for the current task.
 *	@tcred points to the cred structure for the target task.
 *	@flags contains the LSM_PRLIMIT_* flag bits indicating whether the
 *	resource limits are being read, modified, or both.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_prlimit(const struct cred *cred, const struct cred *tcred,
			    unsigned int flags)
{
	return 0;
}

static int acslinux_task_setioprio(struct task_struct *p, int ioprio)
{
	return 0;
}

/** @task_setnice:
 *	Check permission before setting the nice value of @p to @nice.
 *	@p contains the task_struct of process.
 *	@nice contains the new nice value.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_setnice(struct task_struct *p, int nice)
{
	return 0;
}

/** @task_setpgid:
 *	Check permission before setting the process group identifier of the
 *	process @p to @pgid.
 *	@p contains the task_struct for process being modified.
 *	@pgid contains the new pgid.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

/** @task_setrlimit:
 *	Check permission before setting the resource limits of process @p
 *	for @resource to @new_rlim.  The old resource limit values can
 *	be examined by dereferencing (p->signal->rlim + resource).
 *	@p points to the task_struct for the target task's group leader.
 *	@resource contains the resource whose limit is being set.
 *	@new_rlim contains the new limits for @resource.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_setrlimit(struct task_struct *p, unsigned int resource,
				struct rlimit *new_rlim)
{
	return 0;
}

/** @task_setscheduler:
 *	Check permission before setting scheduling policy and/or parameters of
 *	process @p based on @policy and @lp.
 *	@p contains the task_struct for process.
 *	@policy contains the scheduling policy.
 *	@lp contains the scheduling parameters.
 *	Return 0 if permission is granted.
 */
static int acslinux_task_setscheduler(struct task_struct *p)
{
	return 0;
}

/** @task_to_inode:
 *	Set the security attributes for an inode based on an associated task's
 *	security attributes, e.g. for /proc/pid inodes.
 *	@p contains the task_struct for the task.
 *	@inode contains the inode structure for the inode.
 */
static void acslinux_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

/** @vm_enough_memory:
 *	Check permissions for allocating a new virtual mapping.
 *	@mm contains the mm struct it is being added to.
 *	@pages contains the number of pages.
 *	Return 0 if permission is granted.
 */
static int acslinux_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}



#ifdef CONFIG_AUDIT

/** @audit_rule_free:
 *	Deallocate the LSM audit rule structure previously allocated by
 *	audit_rule_init.
 *	@rule contains the allocated rule
 */
static void acslinux_audit_rule_free(void *lsmrule)
{
}

/** @audit_rule_init:
 *	Allocate and initialize an LSM audit rule structure.
 *	@field contains the required Audit action.
 *	Fields flags are defined in include/linux/audit.h
 *	@op contains the operator the rule uses.
 *	@rulestr contains the context where the rule will be applied to.
 *	@lsmrule contains a pointer to receive the result.
 *	Return 0 if @lsmrule has been successfully set,
 *	-EINVAL in case of an invalid rule.
 */
static int acslinux_audit_rule_init(u32 field, u32 op, char *rulestr,
				void **lsmrule)
{
	return 0;
}

/** @audit_rule_known:
 *	Specifies whether given @rule contains any fields related to
 *	current LSM.
 *	@rule contains the audit rule of interest.
 *	Return 1 in case of relation found, 0 otherwise.
 */
static int acslinux_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

/** @audit_rule_match:
 *	Determine if given @secid matches a rule previously approved
 *	by @audit_rule_known.
 *	@secid contains the security id in question.
 *	@field contains the field which relates to current LSM.
 *	@op contains the operator that will be used for matching.
 *	@rule points to the audit rule that will be checked against.
 *	@actx points to the audit context associated with the check.
 *	Return 1 if secid matches the rule, 0 if it does not, -ERRNO on failure.
 */
static int acslinux_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

#endif /* CONFIG_AUDIT */

#ifdef CONFIG_BPF_SYSCALL

/** @bpf:
 *	Do a initial check for all bpf syscalls after the attribute is copied
 *	into the kernel. The actual security module can implement their own
 *	rules to check the specific cmd they need.
 */
static int acslinux_bpf(int cmd, union bpf_attr *attr,
				 unsigned int size)
{
	return 0;
}

/** @bpf_map:
 *	Do a check when the kernel generate and return a file descriptor for
 *	eBPF maps.
 */
static int acslinux_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	return 0;
}

/** @bpf_map_alloc_security:
 *	Initialize the security field inside bpf map.
 */
static int acslinux_bpf_map_alloc_security(struct bpf_map *map)
{
	return 0;
}

/** @bpf_map_free_security:
 *	Clean up the security information stored inside bpf map.
 */
static void acslinux_bpf_map_free_security(struct bpf_map *map)
{
}

/** @bpf_prog:
 *	Do a check when the kernel generate and return a file descriptor for
 *	eBPF programs.
 */
static int acslinux_bpf_prog(struct bpf_prog *prog)
{
	return 0;
}

/** @bpf_prog_alloc_security:
 *	Initialize the security field inside bpf program.
 */
static int acslinux_bpf_prog_alloc_security(struct bpf_prog_aux *aux)
{
	return 0;
}

/** @bpf_prog_free_security:
 *	Clean up the security information stored inside bpf prog.
 */
static void acslinux_bpf_prog_free_security(struct bpf_prog_aux *aux)
{
}

#endif /* CONFIG_BPF_SYSCALL */

#ifdef CONFIG_KEYS

/** @key_alloc:
 *	Permit allocation of a key and assign security data. Note that key does
 *	not have a serial number assigned at this point.
 *	@key points to the key.
 *	@flags is the allocation flags
 *	Return 0 if permission is granted, -ve error otherwise.
 */
static int acslinux_key_alloc(struct key *key, const struct cred *cred,
				unsigned long flags)
{
	return 0;
}

/** @key_free:
 *	Notification of destruction; free security data.
 *	@key points to the key.
 *	No return value.
 */
static void acslinux_key_free(struct key *key)
{
}

/** @key_getsecurity:
 *	Get a textual representation of the security context attached to a key
 *	for the purposes of honouring KEYCTL_GETSECURITY.  This function
 *	allocates the storage for the NUL-terminated string and the caller
 *	should free it.
 *	@key points to the key to be queried.
 *	@_buffer points to a pointer that should be set to point to the
 *	resulting string (if no label or an error occurs).
 *	Return the length of the string (including terminating NUL) or -ve if
 *	an error.
 *	May also return 0 (and a NULL buffer pointer) if there is no label.
 */
static int acslinux_key_getsecurity(struct key *key, char **_buffer)
{
	return 0;
}

/** @key_permission:
 *	See whether a specific operational right is granted to a process on a
 *	key.
 *	@key_ref refers to the key (key pointer + possession attribute bit).
 *	@cred points to the credentials to provide the context against which to
 *	evaluate the security data on the key.
 *	@perm describes the combination of permissions required of this key.
 *	Return 0 if permission is granted, -ve error otherwise.
 */
static int acslinux_key_permission(key_ref_t key_ref, const struct cred *cred,
				unsigned perm)
{
	return 0;
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_SECURITY_INFINIBAND

/** @ib_alloc_security:
 *	Allocate a security structure for Infiniband objects.
 *	@sec pointer to a security structure pointer.
 *	Returns 0 on success, non-zero on failure
 */
static int acslinux_ib_alloc_security(void **sec)
{
	return 0;
}

/** @ib_endport_manage_subnet:
 *	Check permissions to send and receive SMPs on a end port.
 *	@dev_name the IB device name (i.e. mlx4_0).
 *	@port_num the port number.
 *	@sec pointer to a security structure.
 */
static int acslinux_ib_endport_manage_subnet(void *sec, const char *dev_name,
					u8 port_num)
{
	return 0;
}

/** @ib_free_security:
 *	Deallocate an Infiniband security structure.
 *	@sec contains the security structure to be freed.
 */
static void acslinux_ib_free_security(void *sec)
{
}

/** @ib_pkey_access:
 *	Check permission to access a pkey when modifing a QP.
 *	@subnet_prefix the subnet prefix of the port being used.
 *	@pkey the pkey to be accessed.
 *	@sec pointer to a security structure.
 */
static int acslinux_ib_pkey_access(void *sec, u64 subnet_prefix, u16 pkey)
{
	return 0;
}

#endif /* CONFIG_SECURITY_INFINIBAND */

#ifdef CONFIG_SECURITY_NETWORK

/** @inet_conn_established:
 *	Sets the connection's peersid to the secmark on skb.
 */
static void acslinux_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

/** @inet_conn_request:
 *	Sets the openreq's sid to socket's sid with MLS portion taken
 *	from peer sid.
 */
static int acslinux_inet_conn_request(struct sock *sk, struct sk_buff *skb,
					struct request_sock *req)
{
	return 0;
}

/** @inet_csk_clone:
 *	Sets the new child socket's sid to the openreq sid.
 */
static void acslinux_inet_csk_clone(struct sock *newsk,
				const struct request_sock *req)
{
}

/** @req_classify_flow:
 *	Sets the flow's sid to the openreq sid.
 */
static void acslinux_req_classify_flow(const struct request_sock *req,
					struct flowi *fl)
{
}

/** @sctp_assoc_request:
 *	Passes the @ep and @chunk->skb of the association INIT packet to
 *	the security module.
 *	@ep pointer to sctp endpoint structure.
 *	@skb pointer to skbuff of association packet.
 *	Return 0 on success, error on failure.
 */
static int acslinux_sctp_assoc_request(struct sctp_endpoint *ep,
				  struct sk_buff *skb)
{
	return 0;
}

/** @sctp_bind_connect:
 *	Validiate permissions required for each address associated with sock
 *	@sk. Depending on @optname, the addresses will be treated as either
 *	for a connect or bind service. The @addrlen is calculated on each
 *	ipv4 and ipv6 address using sizeof(struct sockaddr_in) or
 *	sizeof(struct sockaddr_in6).
 *	@sk pointer to sock structure.
 *	@optname name of the option to validate.
 *	@address list containing one or more ipv4/ipv6 addresses.
 *	@addrlen total length of address(s).
 *	Return 0 on success, error on failure.
 */
static int acslinux_sctp_bind_connect(struct sock *sk, int optname,
				 struct sockaddr *address, int addrlen)
{
	return 0;
}

/** @sctp_sk_clone:
 *	Called whenever a new socket is created by accept(2) (i.e. a TCP
 *	style socket) or when a socket is 'peeled off' e.g userspace
 *	calls sctp_peeloff(3).
 *	@ep pointer to current sctp endpoint structure.
 *	@sk pointer to current sock structure.
 *	@sk pointer to new sock structure.
 */
static void acslinux_sctp_sk_clone(struct sctp_endpoint *ep, struct sock *sk,
			      struct sock *newsk)
{
}

static void acslinux_secmark_refcount_dec(void)
{
}

static void acslinux_secmark_refcount_inc(void)
{
}

/** @secmark_relabel_packet:
 *	check if the process should be allowed to relabel packets to
 *	the given secid
 */
static int acslinux_secmark_relabel_packet(u32 secid)
{
	return 0;
}

/** @sk_alloc_security:
 *	Allocate and attach a security structure to the sk->sk_security field,
 *	which is used to copy security attributes between local stream sockets.
 */
static int acslinux_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

/** @sk_clone_security:
 *	Clone/copy security structure.
 */
static void acslinux_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

/** @sk_free_security:
 *	Deallocate security structure.
 */
static void acslinux_sk_free_security(struct sock *sk)
{
}

/** @sk_getsecid:
 *	Retrieve the LSM-specific secid for the sock to enable caching
 *	of network authorizations.
 */
static void acslinux_sk_getsecid(struct sock *sk, u32 *secid)
{
}

/** @sock_graft:
 *	Sets the socket's isec sid to the sock's sid.
 */
static void acslinux_sock_graft(struct sock *sk, struct socket *parent)
{
}

/** @socket_accept:
 *	Check permission before accepting a new connection.  Note that the new
 *	socket, @newsock, has been created and some information copied to it,
 *	but the accept operation has not actually been performed.
 *	@sock contains the listening socket structure.
 *	@newsock contains the newly created server socket for connection.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

/** @socket_bind:
 *	Check permission before socket protocol layer bind operation is
 *	performed and the socket @sock is bound to the address specified in the
 *	@address parameter.
 *	@sock contains the socket structure.
 *	@address contains the address to bind to.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen)
{
	return 0;
}

/** @socket_connect:
 *	Check permission before socket protocol layer connect operation
 *	attempts to connect socket @sock to a remote address, @address.
 *	@sock contains the socket structure.
 *	@address contains the address of remote endpoint.
 *	@addrlen contains the length of address.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_connect(struct socket *sock, struct sockaddr *address,
				int addrlen)
{
	return 0;
}

/** @socket_create:
 *	Check permissions prior to creating a new socket.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_create(int family, int type, int protocol, int kern)
{
	return 0;
}

/** @socket_getpeername:
 *	Check permission before the remote address (name) of a socket object
 *	@sock is retrieved.
 *	@sock contains the socket structure.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_getpeername(struct socket *sock)
{
	return 0;
}

/** @socket_getpeersec_dgram:
 *	This hook allows the security module to provide peer socket security
 *	state for udp sockets on a per-packet basis to userspace via
 *	getsockopt SO_GETPEERSEC.  The application must first have indicated
 *	the IP_PASSSEC option via getsockopt.  It can then retrieve the
 *	security state returned by this hook for a packet via the SCM_SECURITY
 *	ancillary message type.
 *	@skb is the skbuff for the packet being queried
 *	@secdata is a pointer to a buffer in which to copy the security data
 *	@seclen is the maximum length for @secdata
 *	Return 0 on success, error on failure.
 */
static int acslinux_socket_getpeersec_dgram(struct socket *sock,
					struct sk_buff *skb, u32 *secid)
{
	return 0;
}

/** @socket_getpeersec_stream:
 *	This hook allows the security module to provide peer socket security
 *	state for unix or connected tcp sockets to userspace via getsockopt
 *	SO_GETPEERSEC.  For tcp sockets this can be meaningful if the
 *	socket is associated with an ipsec SA.
 *	@sock is the local socket.
 *	@optval userspace memory where the security state is to be copied.
 *	@optlen userspace int where the module should copy the actual length
 *	of the security state.
 *	@len as input is the maximum length to copy to userspace provided
 *	by the caller.
 *	Return 0 if all is well, otherwise, typical getsockopt return
 *	values.
 */
static int acslinux_socket_getpeersec_stream(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len)
{
	return 0;
}

/** @socket_getsockname:
 *	Check permission before the local address (name) of the socket object
 *	@sock is retrieved.
 *	@sock contains the socket structure.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_getsockname(struct socket *sock)
{
	return 0;
}

/** @socket_getsockopt:
 *	Check permissions before retrieving the options associated with socket
 *	@sock.
 *	@sock contains the socket structure.
 *	@level contains the protocol level to retrieve option from.
 *	@optname contains the name of option to retrieve.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

/** @socket_listen:
 *	Check permission before socket protocol layer listen operation.
 *	@sock contains the socket structure.
 *	@backlog contains the maximum length for the pending connection queue.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

/** @socket_post_create:
 *	This hook allows a module to update or allocate a per-socket security
 *	structure. Note that the security field was not added directly to the
 *	socket structure, but rather, the socket security information is stored
 *	in the associated inode.  Typically, the inode alloc_security hook will
 *	allocate and and attach security information to
 *	sock->inode->i_security.  This hook may be used to update the
 *	sock->inode->i_security field with additional information that wasn't
 *	available when the inode was allocated.
 *	@sock contains the newly created socket structure.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 */
static int acslinux_socket_post_create(struct socket *sock, int family, int type,
					int protocol, int kern)
{
	return 0;
}

/** @socket_recvmsg:
 *	Check permission before receiving a message from a socket.
 *	@sock contains the socket structure.
 *	@msg contains the message structure.
 *	@size contains the size of message structure.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				int size, int flags)
{
	return 0;
}

/** @socket_sendmsg:
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				int size)
{
	return 0;
}

/** @socket_setsockopt:
 *	Check permissions before setting the options associated with socket
 *	@sock.
 *	@sock contains the socket structure.
 *	@level contains the protocol level to set options for.
 *	@optname contains the name of the option to set.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

/** @socket_shutdown:
 *	Checks permission before all or part of a connection on the socket
 *	@sock is shut down.
 *	@sock contains the socket structure.
 *	@how contains the flag indicating how future sends and receives
 *	are handled.
 *	Return 0 if permission is granted.
 */
static int acslinux_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

/** @socket_sock_rcv_skb:
 *	Check permissions on incoming network packets.  This hook is distinct
 *	from Netfilter's IP input hooks since it is the first time that the
 *	incoming sk_buff @skb has been associated with a particular socket, @sk.
 *	Must not sleep inside this hook because some callers hold spinlocks.
 *	@sk contains the sock (not socket) associated with the incoming sk_buff.
 *	@skb contains the incoming network data.
 */
static int acslinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

/** @tun_dev_alloc_security:
 *	This hook allows a module to allocate a security structure for a TUN
 *	device.
 *	@security pointer to a security structure pointer.
 *	Returns a zero on success, negative values on failure.
 */
static int acslinux_tun_dev_alloc_security(void **security)
{
	return 0;
}

/** @tun_dev_attach:
 *	This hook can be used by the module to update any security state
 *	associated with the TUN device's sock structure.
 *	@sk contains the existing sock structure.
 *	@security pointer to the TUN device's security structure.
 */
static int acslinux_tun_dev_attach(struct sock *sk, void *security)
{
	return 0;
}

/** @tun_dev_attach_queue:
 *	Check permissions prior to attaching to a TUN device queue.
 *	@security pointer to the TUN device's security structure.
 */
static int acslinux_tun_dev_attach_queue(void *security)
{
	return 0;
}

/** @tun_dev_create:
 *	Check permissions prior to creating a new TUN device.
 */
static int acslinux_tun_dev_create(void)
{
	return 0;
}

/** @tun_dev_free_security:
 *	This hook allows a module to free the security structure for a TUN
 *	device.
 *	@security pointer to the TUN device's security structure
 */
static void acslinux_tun_dev_free_security(void *security)
{
}

/** @tun_dev_open:
 *	This hook can be used by the module to update any security state
 *	associated with the TUN device's security structure.
 *	@security pointer to the TUN devices's security structure.
 */
static int acslinux_tun_dev_open(void *security)
{
	return 0;
}

/** @unix_may_send:
 *	Check permissions before connecting or sending datagrams from @sock to
 *	@other.
 *	@sock contains the socket structure.
 *	@other contains the peer socket structure.
 *	Return 0 if permission is granted.
 */
static int acslinux_unix_may_send(struct socket *sock, struct socket *other)
{
	return 0;
}

/** @unix_stream_connect:
 *	Check permissions before establishing a Unix domain stream connection
 *	between @sock and @other.
 *	@sock contains the sock structure.
 *	@other contains the peer sock structure.
 *	@newsk contains the new sock structure.
 *	Return 0 if permission is granted.
 */
static int acslinux_unix_stream_connect(struct sock *sock, struct sock *other,
					struct sock *newsk)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/** @xfrm_decode_session:
 *	@skb points to skb to decode.
 *	@secid points to the flow key secid to set.
 *	@ckall says if all xfrms used should be checked for same secid.
 *	Return 0 if ckall is zero or all xfrms used have the same secid.
 */
static int acslinux_xfrm_decode_session(struct sk_buff *skb, u32 *secid, int ckall)
{
	return 0;
}

/** @xfrm_policy_alloc_security:
 *	@ctxp is a pointer to the xfrm_sec_ctx being added to Security Policy
 *	Database used by the XFRM system.
 *	@sec_ctx contains the security context information being provided by
 *	the user-level policy update program (e.g., setkey).
 *	Allocate a security structure to the xp->security field; the security
 *	field is initialized to NULL when the xfrm_policy is allocated.
 *	Return 0 if operation was successful (memory to allocate, legal context)
 *	@gfp is to specify the context for the allocation
 */
static int acslinux_xfrm_policy_alloc_security(struct xfrm_sec_ctx **ctxp,
					  struct xfrm_user_sec_ctx *sec_ctx,
						gfp_t gfp)
{
	return 0;
}

/** @xfrm_policy_clone_security:
 *	@old_ctx contains an existing xfrm_sec_ctx.
 *	@new_ctxp contains a new xfrm_sec_ctx being cloned from old.
 *	Allocate a security structure in new_ctxp that contains the
 *	information from the old_ctx structure.
 *	Return 0 if operation was successful (memory to allocate).
 */
static int acslinux_xfrm_policy_clone_security(struct xfrm_sec_ctx *old_ctx,
						struct xfrm_sec_ctx **new_ctx)
{
	return 0;
}

/** @xfrm_policy_delete_security:
 *	@ctx contains the xfrm_sec_ctx.
 *	Authorize deletion of xp->security.
 */
static int acslinux_xfrm_policy_delete_security(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

/** @xfrm_policy_free_security:
 *	@ctx contains the xfrm_sec_ctx
 *	Deallocate xp->security.
 */
static void acslinux_xfrm_policy_free_security(struct xfrm_sec_ctx *ctx)
{
}

/** @xfrm_policy_lookup:
 *	@ctx contains the xfrm_sec_ctx for which the access control is being
 *	checked.
 *	@fl_secid contains the flow security label that is used to authorize
 *	access to the policy xp.
 *	@dir contains the direction of the flow (input or output).
 *	Check permission when a flow selects a xfrm_policy for processing
 *	XFRMs on a packet.  The hook is called when selecting either a
 *	per-socket policy or a generic xfrm policy.
 *	Return 0 if permission is granted, -ESRCH otherwise, or -errno
 *	on other errors.
 */
static int acslinux_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid,
					u8 dir)
{
	return 0;
}

/** @xfrm_state_alloc:
 *	@x contains the xfrm_state being added to the Security Association
 *	Database by the XFRM system.
 *	@sec_ctx contains the security context information being provided by
 *	the user-level SA generation program (e.g., setkey or racoon).
 *	Allocate a security structure to the x->security field; the security
 *	field is initialized to NULL when the xfrm_state is allocated. Set the
 *	context to correspond to sec_ctx. Return 0 if operation was successful
 *	(memory to allocate, legal context).
 */
static int acslinux_xfrm_state_alloc(struct xfrm_state *x,
				struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

/** @xfrm_state_alloc_acquire:
 *	@x contains the xfrm_state being added to the Security Association
 *	Database by the XFRM system.
 *	@polsec contains the policy's security context.
 *	@secid contains the secid from which to take the mls portion of the
 *	context.
 *	Allocate a security structure to the x->security field; the security
 *	field is initialized to NULL when the xfrm_state is allocated. Set the
 *	context to correspond to secid. Return 0 if operation was successful
 *	(memory to allocate, legal context).
 */
static int acslinux_xfrm_state_alloc_acquire(struct xfrm_state *x,
					struct xfrm_sec_ctx *polsec,
					u32 secid)
{
	return 0;
}

/** @xfrm_state_delete_security:
 *	@x contains the xfrm_state.
 *	Authorize deletion of x->security.
 */
static int acslinux_xfrm_state_delete_security(struct xfrm_state *x)
{
	return 0;
}

/** @xfrm_state_free_security:
 *	@x contains the xfrm_state.
 *	Deallocate x->security.
 */
static void acslinux_xfrm_state_free_security(struct xfrm_state *x)
{
}

/** @xfrm_state_pol_flow_match:
 *	@x contains the state to match.
 *	@xp contains the policy to check for a match.
 *	@fl contains the flow to check for a match.
 *	Return 1 if there is a match.
 */
static int acslinux_xfrm_state_pol_flow_match(struct xfrm_state *x,
						struct xfrm_policy *xp,
						const struct flowi *fl)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_SECURITY_PATH

/** @path_chmod:
 *	Check for permission to change DAC's permission of a file or directory.
 *	@dentry contains the dentry structure.
 *	@mnt contains the vfsmnt structure.
 *	@mode contains DAC's mode.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_chmod(const struct path *path, umode_t mode)
{
	return 0;
}

/** @path_chown:
 *	Check for permission to change owner/group of a file or directory.
 *	@path contains the path structure.
 *	@uid contains new owner's ID.
 *	@gid contains new group's ID.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	return 0;
}

/** @path_chroot:
 *	Check for permission to change root directory.
 *	@path contains the path structure.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_chroot(const struct path *path)
{
	return 0;
}

/** @path_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing link
 *	to the file.
 *	@new_dir contains the path structure of the parent directory of
 *	the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_link(struct dentry *old_dentry, const struct path *new_dir,
				struct dentry *new_dentry)
{
	return 0;
}

/** @path_mkdir:
 *	Check permissions to create a new directory in the existing directory
 *	associated with path structure @path.
 *	@dir contains the path structure of parent of the directory
 *	to be created.
 *	@dentry contains the dentry structure of new directory.
 *	@mode contains the mode of new directory.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_mkdir(const struct path *dir, struct dentry *dentry,
				umode_t mode)
{
	return 0;
}

/** @path_mknod:
 *	Check permissions when creating a file. Note that this hook is called
 *	even if mknod operation is being done for a regular file.
 *	@dir contains the path structure of parent of the new file.
 *	@dentry contains the dentry structure of the new file.
 *	@mode contains the mode of the new file.
 *	@dev contains the undecoded device number. Use new_decode_dev() to get
 *	the decoded device number.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_mknod(const struct path *dir, struct dentry *dentry,
				umode_t mode, unsigned int dev)
{
	return 0;
}

/** @path_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the path structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the path structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_rename(const struct path *old_dir, struct dentry *old_dentry,
				const struct path *new_dir,
				struct dentry *new_dentry)
{
	return 0;
}

/** @path_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the path structure of parent of the directory to be
 *	removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	return 0;
}

/** @path_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the path structure of parent directory of
 *	the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_symlink(const struct path *dir, struct dentry *dentry,
				const char *old_name)
{
	return 0;
}

/** @path_truncate:
 *	Check permission before truncating a file.
 *	@path contains the path structure for the file.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_truncate(const struct path *path)
{
	return 0;
}

/** @path_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the path structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 */
static int acslinux_path_unlink(const struct path *dir, struct dentry *dentry)
{
	return 0;
}

#endif /* CONFIG_SECURITY_PATH */

static struct security_hook_list acslinux_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(binder_set_context_mgr, acslinux_binder_set_context_mgr),
	LSM_HOOK_INIT(binder_transaction, acslinux_binder_transaction),
	LSM_HOOK_INIT(binder_transfer_binder, acslinux_binder_transfer_binder),
	LSM_HOOK_INIT(binder_transfer_file, acslinux_binder_transfer_file),
	LSM_HOOK_INIT(bprm_check_security, acslinux_bprm_check_security),
	LSM_HOOK_INIT(bprm_committed_creds, acslinux_bprm_committed_creds),
	LSM_HOOK_INIT(bprm_committing_creds, acslinux_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_set_creds, acslinux_bprm_set_creds),
	LSM_HOOK_INIT(capable, acslinux_capable),
	LSM_HOOK_INIT(capget, acslinux_capget),
	LSM_HOOK_INIT(capset, acslinux_capset),
	LSM_HOOK_INIT(cred_alloc_blank, acslinux_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, acslinux_cred_free),
	LSM_HOOK_INIT(cred_getsecid, acslinux_cred_getsecid),
	LSM_HOOK_INIT(cred_prepare, acslinux_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, acslinux_cred_transfer),
	LSM_HOOK_INIT(d_instantiate, acslinux_d_instantiate),
	LSM_HOOK_INIT(dentry_create_files_as, acslinux_dentry_create_files_as),
	LSM_HOOK_INIT(dentry_init_security, acslinux_dentry_init_security),
	LSM_HOOK_INIT(file_alloc_security, acslinux_file_alloc_security),
	LSM_HOOK_INIT(file_fcntl, acslinux_file_fcntl),
	LSM_HOOK_INIT(file_free_security, acslinux_file_free_security),
	LSM_HOOK_INIT(file_ioctl, acslinux_file_ioctl),
	LSM_HOOK_INIT(file_lock, acslinux_file_lock),
	LSM_HOOK_INIT(file_mprotect, acslinux_file_mprotect),
	LSM_HOOK_INIT(file_open, acslinux_file_open),
	LSM_HOOK_INIT(file_permission, acslinux_file_permission),
	LSM_HOOK_INIT(file_receive, acslinux_file_receive),
	LSM_HOOK_INIT(file_send_sigiotask, acslinux_file_send_sigiotask),
	LSM_HOOK_INIT(file_set_fowner, acslinux_file_set_fowner),
	LSM_HOOK_INIT(getprocattr, acslinux_getprocattr),
	LSM_HOOK_INIT(inode_alloc_security, acslinux_inode_alloc_security),
	LSM_HOOK_INIT(inode_copy_up, acslinux_inode_copy_up),
	LSM_HOOK_INIT(inode_copy_up_xattr, acslinux_inode_copy_up_xattr),
	LSM_HOOK_INIT(inode_create, acslinux_inode_create),
	LSM_HOOK_INIT(inode_follow_link, acslinux_inode_follow_link),
	LSM_HOOK_INIT(inode_free_security, acslinux_inode_free_security),
	LSM_HOOK_INIT(inode_getattr, acslinux_inode_getattr),
	LSM_HOOK_INIT(inode_getsecctx, acslinux_inode_getsecctx),
	LSM_HOOK_INIT(inode_getsecid, acslinux_inode_getsecid),
	LSM_HOOK_INIT(inode_getsecurity, acslinux_inode_getsecurity),
	LSM_HOOK_INIT(inode_getxattr, acslinux_inode_getxattr),
	LSM_HOOK_INIT(inode_init_security, acslinux_inode_init_security),
	LSM_HOOK_INIT(inode_invalidate_secctx, acslinux_inode_invalidate_secctx),
	LSM_HOOK_INIT(inode_killpriv, acslinux_inode_killpriv),
	LSM_HOOK_INIT(inode_link, acslinux_inode_link),
	LSM_HOOK_INIT(inode_listsecurity, acslinux_inode_listsecurity),
	LSM_HOOK_INIT(inode_listxattr, acslinux_inode_listxattr),
	LSM_HOOK_INIT(inode_mkdir, acslinux_inode_mkdir),
	LSM_HOOK_INIT(inode_mknod, acslinux_inode_mknod),
	LSM_HOOK_INIT(inode_need_killpriv, acslinux_inode_need_killpriv),
	LSM_HOOK_INIT(inode_notifysecctx, acslinux_inode_notifysecctx),
	LSM_HOOK_INIT(inode_permission, acslinux_inode_permission),
	LSM_HOOK_INIT(inode_post_setxattr, acslinux_inode_post_setxattr),
	LSM_HOOK_INIT(inode_readlink, acslinux_inode_readlink),
	LSM_HOOK_INIT(inode_removexattr, acslinux_inode_removexattr),
	LSM_HOOK_INIT(inode_rename, acslinux_inode_rename),
	LSM_HOOK_INIT(inode_rmdir, acslinux_inode_rmdir),
	LSM_HOOK_INIT(inode_setattr, acslinux_inode_setattr),
	LSM_HOOK_INIT(inode_setsecctx, acslinux_inode_setsecctx),
	LSM_HOOK_INIT(inode_setsecurity, acslinux_inode_setsecurity),
	LSM_HOOK_INIT(inode_setxattr, acslinux_inode_setxattr),
	LSM_HOOK_INIT(inode_symlink, acslinux_inode_symlink),
	LSM_HOOK_INIT(inode_unlink, acslinux_inode_unlink),
	LSM_HOOK_INIT(ipc_getsecid, acslinux_ipc_getsecid),
	LSM_HOOK_INIT(ipc_permission, acslinux_ipc_permission),
	LSM_HOOK_INIT(ismaclabel, acslinux_ismaclabel),
	LSM_HOOK_INIT(kernel_act_as, acslinux_kernel_act_as),
	LSM_HOOK_INIT(kernel_create_files_as, acslinux_kernel_create_files_as),
	LSM_HOOK_INIT(kernel_module_request, acslinux_kernel_module_request),
	LSM_HOOK_INIT(kernel_post_read_file, acslinux_kernel_post_read_file),
	LSM_HOOK_INIT(kernel_read_file, acslinux_kernel_read_file),
	LSM_HOOK_INIT(mmap_addr, acslinux_mmap_addr),
	LSM_HOOK_INIT(mmap_file, acslinux_mmap_file),
	LSM_HOOK_INIT(msg_msg_alloc_security, acslinux_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security, acslinux_msg_msg_free_security),
	LSM_HOOK_INIT(msg_queue_alloc_security, acslinux_msg_queue_alloc_security),
	LSM_HOOK_INIT(msg_queue_associate, acslinux_msg_queue_associate),
	LSM_HOOK_INIT(msg_queue_free_security, acslinux_msg_queue_free_security),
	LSM_HOOK_INIT(msg_queue_msgctl, acslinux_msg_queue_msgctl),
	LSM_HOOK_INIT(msg_queue_msgrcv, acslinux_msg_queue_msgrcv),
	LSM_HOOK_INIT(msg_queue_msgsnd, acslinux_msg_queue_msgsnd),
	LSM_HOOK_INIT(netlink_send, acslinux_netlink_send),
	LSM_HOOK_INIT(ptrace_access_check, acslinux_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, acslinux_ptrace_traceme),
	LSM_HOOK_INIT(quota_on, acslinux_quota_on),
	LSM_HOOK_INIT(quotactl, acslinux_quotactl),
	LSM_HOOK_INIT(release_secctx, acslinux_release_secctx),
	LSM_HOOK_INIT(sb_alloc_security, acslinux_sb_alloc_security),
	LSM_HOOK_INIT(sb_clone_mnt_opts, acslinux_sb_clone_mnt_opts),
	LSM_HOOK_INIT(sb_copy_data, acslinux_sb_copy_data),
	LSM_HOOK_INIT(sb_free_security, acslinux_sb_free_security),
	LSM_HOOK_INIT(sb_kern_mount, acslinux_sb_kern_mount),
	LSM_HOOK_INIT(sb_mount, acslinux_sb_mount),
	LSM_HOOK_INIT(sb_parse_opts_str, acslinux_sb_parse_opts_str),
	LSM_HOOK_INIT(sb_pivotroot, acslinux_sb_pivotroot),
	LSM_HOOK_INIT(sb_remount, acslinux_sb_remount),
	LSM_HOOK_INIT(sb_set_mnt_opts, acslinux_sb_set_mnt_opts),
	LSM_HOOK_INIT(sb_show_options, acslinux_sb_show_options),
	LSM_HOOK_INIT(sb_statfs, acslinux_sb_statfs),
	LSM_HOOK_INIT(sb_umount, acslinux_sb_umount),
	LSM_HOOK_INIT(secctx_to_secid, acslinux_secctx_to_secid),
	LSM_HOOK_INIT(secid_to_secctx, acslinux_secid_to_secctx),
	LSM_HOOK_INIT(sem_alloc_security, acslinux_sem_alloc_security),
	LSM_HOOK_INIT(sem_associate, acslinux_sem_associate),
	LSM_HOOK_INIT(sem_free_security, acslinux_sem_free_security),
	LSM_HOOK_INIT(sem_semctl, acslinux_sem_semctl),
	LSM_HOOK_INIT(sem_semop, acslinux_sem_semop),
	LSM_HOOK_INIT(setprocattr, acslinux_setprocattr),
	LSM_HOOK_INIT(settime, acslinux_settime),
	LSM_HOOK_INIT(shm_alloc_security, acslinux_shm_alloc_security),
	LSM_HOOK_INIT(shm_associate, acslinux_shm_associate),
	LSM_HOOK_INIT(shm_free_security, acslinux_shm_free_security),
	LSM_HOOK_INIT(shm_shmat, acslinux_shm_shmat),
	LSM_HOOK_INIT(shm_shmctl, acslinux_shm_shmctl),
	LSM_HOOK_INIT(syslog, acslinux_syslog),
	LSM_HOOK_INIT(task_alloc, acslinux_task_alloc),
	LSM_HOOK_INIT(task_fix_setuid, acslinux_task_fix_setuid),
	LSM_HOOK_INIT(task_free, acslinux_task_free),
	LSM_HOOK_INIT(task_getioprio, acslinux_task_getioprio),
	LSM_HOOK_INIT(task_getpgid, acslinux_task_getpgid),
	LSM_HOOK_INIT(task_getscheduler, acslinux_task_getscheduler),
	LSM_HOOK_INIT(task_getsecid, acslinux_task_getsecid),
	LSM_HOOK_INIT(task_getsid, acslinux_task_getsid),
	LSM_HOOK_INIT(task_kill, acslinux_task_kill),
	LSM_HOOK_INIT(task_movememory, acslinux_task_movememory),
	LSM_HOOK_INIT(task_prctl, acslinux_task_prctl),
	LSM_HOOK_INIT(task_prlimit, acslinux_task_prlimit),
	LSM_HOOK_INIT(task_setioprio, acslinux_task_setioprio),
	LSM_HOOK_INIT(task_setnice, acslinux_task_setnice),
	LSM_HOOK_INIT(task_setpgid, acslinux_task_setpgid),
	LSM_HOOK_INIT(task_setrlimit, acslinux_task_setrlimit),
	LSM_HOOK_INIT(task_setscheduler, acslinux_task_setscheduler),
	LSM_HOOK_INIT(task_to_inode, acslinux_task_to_inode),
	LSM_HOOK_INIT(vm_enough_memory, acslinux_vm_enough_memory),

#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(audit_rule_free, acslinux_audit_rule_free),
	LSM_HOOK_INIT(audit_rule_init, acslinux_audit_rule_init),
	LSM_HOOK_INIT(audit_rule_known, acslinux_audit_rule_known),
	LSM_HOOK_INIT(audit_rule_match, acslinux_audit_rule_match),
#endif
#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf, acslinux_bpf),
	LSM_HOOK_INIT(bpf_map, acslinux_bpf_map),
	LSM_HOOK_INIT(bpf_map_alloc_security, acslinux_bpf_map_alloc_security),
	LSM_HOOK_INIT(bpf_map_free_security, acslinux_bpf_map_free_security),
	LSM_HOOK_INIT(bpf_prog, acslinux_bpf_prog),
	LSM_HOOK_INIT(bpf_prog_alloc_security, acslinux_bpf_prog_alloc_security),
	LSM_HOOK_INIT(bpf_prog_free_security, acslinux_bpf_prog_free_security),
#endif
#ifdef CONFIG_KEYS
	LSM_HOOK_INIT(key_alloc, acslinux_key_alloc),
	LSM_HOOK_INIT(key_free, acslinux_key_free),
	LSM_HOOK_INIT(key_getsecurity, acslinux_key_getsecurity),
	LSM_HOOK_INIT(key_permission, acslinux_key_permission),
#endif
#ifdef CONFIG_SECURITY_INFINIBAND
	LSM_HOOK_INIT(ib_alloc_security, acslinux_ib_alloc_security),
	LSM_HOOK_INIT(ib_endport_manage_subnet, acslinux_ib_endport_manage_subnet),
	LSM_HOOK_INIT(ib_free_security, acslinux_ib_free_security),
	LSM_HOOK_INIT(ib_pkey_access, acslinux_ib_pkey_access),
#endif
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(inet_conn_established, acslinux_inet_conn_established),
	LSM_HOOK_INIT(inet_conn_request, acslinux_inet_conn_request),
	LSM_HOOK_INIT(inet_csk_clone, acslinux_inet_csk_clone),
	LSM_HOOK_INIT(req_classify_flow, acslinux_req_classify_flow),
	LSM_HOOK_INIT(sctp_assoc_request, acslinux_sctp_assoc_request),
	LSM_HOOK_INIT(sctp_bind_connect, acslinux_sctp_bind_connect),
	LSM_HOOK_INIT(sctp_sk_clone, acslinux_sctp_sk_clone),
	LSM_HOOK_INIT(secmark_refcount_dec, acslinux_secmark_refcount_dec),
	LSM_HOOK_INIT(secmark_refcount_inc, acslinux_secmark_refcount_inc),
	LSM_HOOK_INIT(secmark_relabel_packet, acslinux_secmark_relabel_packet),
	LSM_HOOK_INIT(sk_alloc_security, acslinux_sk_alloc_security),
	LSM_HOOK_INIT(sk_clone_security, acslinux_sk_clone_security),
	LSM_HOOK_INIT(sk_free_security, acslinux_sk_free_security),
	LSM_HOOK_INIT(sk_getsecid, acslinux_sk_getsecid),
	LSM_HOOK_INIT(sock_graft, acslinux_sock_graft),
	LSM_HOOK_INIT(socket_accept, acslinux_socket_accept),
	LSM_HOOK_INIT(socket_bind, acslinux_socket_bind),
	LSM_HOOK_INIT(socket_connect, acslinux_socket_connect),
	LSM_HOOK_INIT(socket_create, acslinux_socket_create),
	LSM_HOOK_INIT(socket_getpeername, acslinux_socket_getpeername),
	LSM_HOOK_INIT(socket_getpeersec_dgram, acslinux_socket_getpeersec_dgram),
	LSM_HOOK_INIT(socket_getpeersec_stream, acslinux_socket_getpeersec_stream),
	LSM_HOOK_INIT(socket_getsockname, acslinux_socket_getsockname),
	LSM_HOOK_INIT(socket_getsockopt, acslinux_socket_getsockopt),
	LSM_HOOK_INIT(socket_listen, acslinux_socket_listen),
	LSM_HOOK_INIT(socket_post_create, acslinux_socket_post_create),
	LSM_HOOK_INIT(socket_recvmsg, acslinux_socket_recvmsg),
	LSM_HOOK_INIT(socket_sendmsg, acslinux_socket_sendmsg),
	LSM_HOOK_INIT(socket_setsockopt, acslinux_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, acslinux_socket_shutdown),
	LSM_HOOK_INIT(socket_sock_rcv_skb, acslinux_socket_sock_rcv_skb),
	LSM_HOOK_INIT(tun_dev_alloc_security, acslinux_tun_dev_alloc_security),
	LSM_HOOK_INIT(tun_dev_attach, acslinux_tun_dev_attach),
	LSM_HOOK_INIT(tun_dev_attach_queue, acslinux_tun_dev_attach_queue),
	LSM_HOOK_INIT(tun_dev_create, acslinux_tun_dev_create),
	LSM_HOOK_INIT(tun_dev_free_security, acslinux_tun_dev_free_security),
	LSM_HOOK_INIT(tun_dev_open, acslinux_tun_dev_open),
	LSM_HOOK_INIT(unix_may_send, acslinux_unix_may_send),
	LSM_HOOK_INIT(unix_stream_connect, acslinux_unix_stream_connect),
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_decode_session, acslinux_xfrm_decode_session),
	LSM_HOOK_INIT(xfrm_policy_alloc_security, acslinux_xfrm_policy_alloc_security),
	LSM_HOOK_INIT(xfrm_policy_clone_security, acslinux_xfrm_policy_clone_security),
	LSM_HOOK_INIT(xfrm_policy_delete_security, acslinux_xfrm_policy_delete_security),
	LSM_HOOK_INIT(xfrm_policy_free_security, acslinux_xfrm_policy_free_security),
	LSM_HOOK_INIT(xfrm_policy_lookup, acslinux_xfrm_policy_lookup),
	LSM_HOOK_INIT(xfrm_state_alloc, acslinux_xfrm_state_alloc),
	LSM_HOOK_INIT(xfrm_state_alloc_acquire, acslinux_xfrm_state_alloc_acquire),
	LSM_HOOK_INIT(xfrm_state_delete_security, acslinux_xfrm_state_delete_security),
	LSM_HOOK_INIT(xfrm_state_free_security, acslinux_xfrm_state_free_security),
	LSM_HOOK_INIT(xfrm_state_pol_flow_match, acslinux_xfrm_state_pol_flow_match),
#endif
#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_chmod, acslinux_path_chmod),
	LSM_HOOK_INIT(path_chown, acslinux_path_chown),
	LSM_HOOK_INIT(path_chroot, acslinux_path_chroot),
	LSM_HOOK_INIT(path_link, acslinux_path_link),
	LSM_HOOK_INIT(path_mkdir, acslinux_path_mkdir),
	LSM_HOOK_INIT(path_mknod, acslinux_path_mknod),
	LSM_HOOK_INIT(path_rename, acslinux_path_rename),
	LSM_HOOK_INIT(path_rmdir, acslinux_path_rmdir),
	LSM_HOOK_INIT(path_symlink, acslinux_path_symlink),
	LSM_HOOK_INIT(path_truncate, acslinux_path_truncate),
	LSM_HOOK_INIT(path_unlink, acslinux_path_unlink),
#endif
};