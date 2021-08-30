#!/usr/sbin/dtrace -s

/*
This script should be of interest to anyone who is encountering
"dynamic variable drops" and is looking to avoid them.

When you get these errors, the suggested approach to fix is:
1. Make sure variables are reset to zero so they can be reclaimed.
2. Increase dynvarsize option (default 1m which means 1mb).
3. Increase cleanrate option (default 101hz: 101 cleared per second).

This script will help you to understand why you're getting dynamic variable
drops, what the errors mean, and whether the above approaches are the correct
ones to use.

The above approaches didn't work for me. There were simply too many variables
being reset per second and the system couldn't keep up.

Background: I have a user-facing character based interface. This has over a
thousand users all typing keystrokes to navigate around the interface and
enter information. A legacy library used by the program has a bug with how it
reads from stdin. We have observed that when read() returns -1 (error reading
from stdin) OR when read() returns 0 (EOF - can occur when user hits the 'X'
on a session instead of closing nicely), the legacy library ignores the error
and simply calls read() again. This is an infinite loop which uses a lot of
CPU.

Hence, the goal is to detect this error in the read from stdin and terminate
the process instead of infintely looping. This will be a long-running script
(i.e. we don't want to encounter problems after running for days/months).

Understanding Dynamic Variable Allocation:
- This D program uses a thread-local 'myproc_fd' variable. This is
  dynamically allocated per myproc process.
- If too many variables are dynamically allocated, then dtrace generates
  the following errors (and these must be eliminated as they mean that
  dtrace will not give correct results):
    dtrace: 4847 dynamic variable drops with non-empty rinsing list
    dtrace: 1162255 dynamic variable drops with non-empty dirty list
- Let's consider the suggested approaches:
  1. Make sure variables are reset to zero so they can be reclaimed.
     - It makes sense that this problem would occur (especially if you have a
       lot of short-lived processes) and some dynamic variables are being left
       around by each process (not reset to zero when process exits, so can 
       never be rinsed/freed).
  2. Increase dynvarsize option (default 1m which means 1mb).
     - This would make sense if you had lots of dynamic variables across lots
       of active processes. In this case, it's not a clean-up issue. You just
       need to allow more space.
  3. Increase cleanrate option (default 101hz: 101 cleared per second).
     - This would make sense if you had lots of dynamic variables on lots of
       short-lived processes. However, needing to change this setting can
       indicate you need a different approach (as per this script).
- In our case, we have a bunch of fairly long running myproc processes that
  are constantly calling read() (for every char typed by the user). If we
  reset our thread-local to zero, then dtrace moves it off self into some
  list for free'ing. Then read() is recalled and allocates another bit of
  memory for the variable. If the number of read() calls (stdin and other
  fds) performed by all myproc processes exceeds the cleanrate (101 per
  second), we'll start getting errors when we hit the dynvarsize limit.
- Rather than increasing cleanrate or dynvarsize to cater for this, a
  better (more scalable and more efficient) approach is to avoid
  resetting our variable to zero (only free it at process termination).

Conclusions:
1. Short-lived processes or processes where the probe is only fired
   infrequently are ok to reset the variable immediately (e.g. set to 1 on
   probe function entry and set to 0 on probe function return).
2. Beware of testing dynamic variables as part of a probe condition. If that
   test is executed, the dynamic variable will be created. The likely solution
   is that the test you use to turn the variable on
   (e.g. /execname == "myproc"/) will need to be repeated in each probe
   condition that needs to test the value of the dynamic variable.
3. For a long-lived process or processes where the probe is fired frequently,
   defer the variable reset until process close (instead of probe function
   return). Use variable values "1" and "2" (or similar) instead of using
   "0" and "1".

When running this D program, all the printf's will go to stdout and any errors
(like variable drops) will go to stderr. Hence, stdout can go to a log file
for monitoring while stderr must be investigated:
  sudo dtrace -s rogueclose.d > monitor.log 2> error.log
*/

#pragma D option quiet
#pragma D option destructive
#pragma D option dynvarsize=4m

dtrace:::BEGIN
{
    printf("%Y, Script started: Tracing read on myproc processes.\n",
           walltimestamp);
}

dtrace:::END
{
    printf("%Y, Script terminated: Restart asap.\n", walltimestamp);
}

/*
Capture read() function entry for myproc stdin.
  ssize_t read(int fd, void * buf, size_t nbyte)

If arg0 (fd) is zero, then this is stdin.

The 'myproc_fd' variable is a thread-local (set/kept per myproc process).
It has the following values:
 0 = Unset (first read() call from the myproc process).
 1 = Currently reading from myproc stdin. As this is a blocking read, we can
     sit in this state for a bit - until we get a char and read() returns.
 2 = Currently reading from another fd OR not currently inside a read().
*/

syscall::read:entry
/execname == "myproc"/
{
    self->myproc_fd = (arg0 == 0) ? 1 : 2; 
}

/*
Capture read() function return for myproc stdin.
- Note: arg1 contains the read() return code.

Note that although we could just check 'self->myproc_fd' here (the check for
[execname == "myproc"] is redundant), we do need that check to avoid dtrace
creating a dynamic variable for self->myproc_fd for non-myproc processes which
in turn would need us to have a higher cleanrate/dynvarsize.

For a -1 return code (error):
- We have observed that myproc doesn't handle this well. For example, when
  errno indicates an EIO error, myproc repeatedly tries to read (each one
  getting the EIO error).
- Note that we need to ignore errno EINTR/EAGAIN as these codes can
  legitimately occur (and are retryable).
*/

syscall::read:return
/execname == "myproc" && self->myproc_fd == 1 && arg1 == -1
                      && errno != EINTR && errno != EAGAIN/
{
    printf("%Y, Stdin IO-Error: killing pid %d for uid %d (errno %d)\n",
	   walltimestamp, pid, uid, errno);

    raise(SIGINT);
}

/*
Similarly, myproc doesn't handle return code 0 well (just retries the read).

A return code of zero occurs for:
- EOF on stdin. This has been observed where user closes their terminal
  without exiting myproc.
- Reading stdin in non-blocking mode (myproc never does this).
*/

syscall::read:return
/execname == "myproc" && self->myproc_fd == 1 && arg1 == 0/
{
    printf("%Y, Stdin EOF: killing pid %d for uid %d\n",
	   walltimestamp, pid, uid);

    raise(SIGINT);
}

/*
Reset our 'myproc_fd' variable to 2 for all read() return cases.

The 'myproc_fd' may currently be 1 for the following cases:
- A positive return code (number of bytes read).
- A negative return code with errno EINTR/EAGAIN.
*/

syscall::read:return
/execname == "myproc" && self->myproc_fd != 2/
{
    self->myproc_fd = 2;
}

/*
When the process exits, clear/free our thread-local variable.

Note that dtrace does not automatically free these variables when a process
terminates. Without this probe, we have observed that after ~ 24 hours
(8000-10000 myproc processes), we start getting "dynamic variable drops"
(due to the dynvarsize limit of 1mb being reached).

Note that this type of probe is often implemented using a "proc:::exit" probe,
but we cannot do that as the current version ("Oracle D 1.11.3") does not
support the "proc" provider.

This probe is fired for most cases of process termination including:
- User exiting myproc using F1/ESC.
- User killing myproc using ctrl+C.
- Sending a signal to kill the myproc process (INT/ABRT/etc).
- The SIGINT from the above raise() calls.

We have noted that this probe is not fired when the myproc process is killed
using the KILL signal. If a few thousand myproc processes were killed in this
way, then the memory would not be cleared and we could start getting "dynamic
variable drops" - requiring the dtrace program to be killed (INT signal) and
restarted.
*/

syscall::rexit:entry
/execname == "myproc"/
{
    self->myproc_fd = 0;
}

