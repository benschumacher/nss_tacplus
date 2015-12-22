# TACACS+ module for Name Service Switch (NSS)

## Building libnss_tacplus.so.2

To build it:

1. You'll need a Linux machine with various build tools (developed/tested
   with CentOS 6.5, should work with 7, as well):

   ```
   $ yum groupinstall -y "Development Tools"
   ```

2. You'll need a recent version of the [pam_tacplus](https://github.com/jeroennijhof/pam_tacplus)
   code checked out from GitHub and build:

   ```
   $ git clone https://github.com/jeroennijhof/pam_tacplus.git
   $ cd pam_tacplus
   $ autoreconf -i && ./configure && make && sudo make install
   ```

3. Acquire the [nss_tacplus](https://github.com/benschumacher/nss_tacplus)
   source, and build the project:
 
   ```
   $ git clone https://github.com/benschumacher/nss_tacplus.git
   $ cd nss_tacplus
   $ make
   ```

4. You should now have a `libnss_tacplus.so.2` library:
 
   ```
   $ ls -l libnss_tacplus.so.2
   -rwxrwxr-x. 1 vagrant vagrant 96759 Sep 19 18:04 libnss_tacplus.so.2*
   ```

5. Profit!

Assuming you've made it this far, you may want to figure out if it works.

## TACACS+ Service Requirements

To provide sufficient information for the Linux-based operating system
running on the host, there are several attribute-value pairs that
must be associated with the user on the ACS server used by the deployment.
User records on Unix-like systems need to have a valid "passwd" record for
the system to operate correctly. Several of these fields can be inferred
during the time of user authentication, but the remaining fields must be
provided by the ACS server.

A standard "passwd" entry on a Unix-like system takes the following form:

   ```
   <username>:<password>:<uid>:<gid>:<gecos>:<home>:<shell>
   ```
 
When authenticating the user via TACACS+, the software can assume values
for the 'username', 'password' and 'gecos' fields, but the others must be
provided by the ACS server. To facilitate this need, the system depends on
the ACS server provided these AVP when responding to a TACACS+
Authorization query for a given 'username':

* `uid`

  A unique integer value greater than or equal to 501 that will serve as
  the numeric user identifier for the TACACS+ authenticated user on the
  host.

* `gid`

  The group identifier or the TACACS+ authenticated user on the host.

* `home`

  The user's home directory on the Linux system. To enable simplier
  management of these systems, the users should be configured with a
  pre-deployed shared home directory based on the role they're assigned
  with the gid.

  * `home=/home/qns-su`

      This should be used for users in the 'qns-su' group
      (`gid=501`)
    
  * `home=/home/qns-admin`

      This should be used for users in the 'qns-admin' group
      (`gid=504`) 
  
  * `home=/home/qns-su`

      This should be used for users in the 'qns-ro' group
      (`gid=505`)

* `shell`

  The system-level login shell of the user. This can be any of the
  installed shells on the host, which can be determined by reviewing the
  contents of '/etc/shells'.
	
  A typically set of shells might include:
	
  * `/bin/sh`
  * `/bin/bash`
  * `/sbin/nologin`
  * `/bin/dash`
  * `/usr/bin/sudosh`

  The `/usr/bin/sudosh` shell can be used to audit user's activity
  on the system. 

## Using TACACS+ NSS module

1. There should be a sample configuration file in the `etc' directory.
   To install it, copy it into your `/etc` directory:
   
   ```
   $ sudo cp tacplus.conf /etc/tacplus.conf
   ```

2. There is also a user-unfriendly tool that you can use to validate that
   the library is working with. You use it like this:
   
   ```
   $ ./dlharness ./libnss_tacplus.so.2 _nss_tacplus_getpwnam_r bschumac
   User `bschumac' found:
   bschumac:x:504:503:bschumac:/home/bschumac:/usr/bin/sudosh
   $ ./dlharness ./libnss_tacplus.so.2 _nss_tacplus_getpwnam_r unknown
   Error: Can't find user `unknown': 0
   ```

   (That's right -- library and symbol names passed in via positional
   arguments. Take that UX-perts.)

   That integer value at the end correlates to an `nss_status' value.
   You can find those documented here: http://goo.gl/Dh6CrE

3. To test the "full stack" solution, you'll need 'nscd' installed,
   as well:
   
   ```
   $ yum install -y nscd
   ```

4. And you'll need to enable the PAM module for TACACS+. First copy the
   'tacacs.pam' file into your /etc/pam.d:
   
   ```
   $ sudo cp tacacs.pam /etc/pam.d/tacacs
   ```

   Then enable it with SSHD by editing '/etc/pam.d/sshd' and make these
   modifications:

   ```
   'auth include tacacs' above 'auth include password-auth'
   'account include tacacs' above 'account include password-auth'
   'session include tacacs' above 'session include password-auth'
   ```

5. Ensure 'nscd' is running:

   ```
   $ service nscd restart
   ```

6. At this point you *should* be able to SSH into the system using
   TACACS+ accounts.

7. If you make changes and need to test something, it may be necessary
   to restart nscd and clear its cache:
   
   ```
   $ sudo service nscd restart
   $ sudo nscd -i passwd
   ```
