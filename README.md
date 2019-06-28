#####*'sans armes, ni haine, ni violence'*

###### Requirments
 - [Paramiko Library](http://www.paramiko.org/)
 
###### Information
Spaggiari scanner comes in 2 versions, a CLI version and an IRC version.

You must edit the config in the IRC version in order to have the bot connect.

###### CLI Commands
**Usage:** spaggiari.py [OPTIONS] [SCAN]

| Option | Description |
| --- | --- |
| -d | enable deep scanning. |
| -f | enable fast scanning. |
| -o \<path> | save output from scan(s) to file. |



| Scan | Description |
| --- | --- |
| -l \<path> | scan a list of ip addresses from file. |
| -x | scan random ip addresses. (does not stop) |
| -r \<class> \<range> | scan a range of ip addresses. |
| -t \<ip> | scan a target ip address. |

Deep scanning uses a larger list of combos to bruteforce with.

###### IRC Commands
| Command | Description |
| --- | --- |
| @random | Scan random ip addresses. |
| @range \<class> \<range> | Scan a range of ip addresses. |
| @range \<class> random | Scan a random range of ip addresses. |
| @status | Check the scanning status on the bot. |
| @stop | Stop all current running scans. |

*Note:* The <class> can be b or c. The <range> is the ip address range prefix to scan.

**CLI Examples:**
* `spaggiari.py -r b 192.168`   *(Scans the range 192.168.0.0-192.168.255.255)*
* `spaggiari.py -r c 192.168.1` *(Scans the range 192.168.1.0-192.168.1.255)*
* `spaggiari.py -r b random`    *(Scans the range ?.?.0.0-?.?.255.255)*
* `spaggiari.py -r c random`    *(Scans the range ?.?.?.0-?.?./.255)*
    
**IRC Examples:**
* `@range b 192.168`   *(Scans the range 192.168.0.0-192.168.255.255)*
* `@range c 192.168.1` *(Scans the range 192.168.1.0-192.168.1.255)*
* `@range b random`    *(Scans the range ?.?.0.0-?.?.255.255)*
* `@range c random`    *(Scans the range ?.?.?.0-?.?./.255)*

###### Python Version Notice
All scripts on this github were developed and written to be used with the latest version of Python.

Check the Python [download page](https://www.python.org/downloads/) for the latest version.

Running the scripts with same major version and not the same major/minor version can cause errors.

###### Mirrors
- [acid.vegas](https://acid.vegas/spaggiari) *(main)*
- [SuperNETs](https://git.supernets.org/acidvegas/spaggiari)
- [GitHub](https://github.com/acidvegas/spaggiari)
- [GitLab](https://gitlab.com/acidvegas/spaggiari)
