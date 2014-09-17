XenVif - The Xen Paravitual Network Class Driver for Windows
============================================================

The XenVif package consists of a single device driver:

*    xenvif.sys is a bus driver which attaches to a virtual device created
     by XenBus and creates a child device for each VIF for XenNet to attach
     to.
     It is also a protocol driver for the netif wire protocol (see
     include\\xen\\io\\netif.h).

Quick Start Guide
=================

Building the driver
-------------------

See BUILD.md

Installing the driver
---------------------

See INSTALL.md

Interfaces
==========

The XenVif package exports the VIF API, as defined by the 'vif_interface'
headers in the include subdirectory. It is important that introduction of
a new API, introduction of a new version of an existing API or retirement
of an old version of an API is managed carefully to avoid incompatibilities
between clients and providers. The general API versioning policy is
described below:

Each distinct set of API versions maps to a PDO revision. The DeviceID of
each PDO created by xenvif.sys will specify the latest revision supported
and all others will be contained within the HardwareIDs and CompatibleIDs.
Hence, when a new version of an API is added, a new PDO revision will be
added. When a version of an API is removed then ALL revisions that API
version maps to will be removed. This is all handled automatically by the
function PdoSetRevisions().

To avoid a situation where a new version of the package is installed that
is incompatible with any child drivers that make use of the APIs, each
child 'subscribes' to an API by writing a registry value with the version
number of that API that they consume into a registry key under the service
key of the providing driver. E.g. if driver 'foo' consumes version 1 of
driver 'bar''s 'widget' API, then it will write
HLKM/CurrentControlSet/Services/BAR/Interfaces/FOO/WIDGET with the value 1.
The 'bar' package co-installer can then check, prior to installation of a
new version of a driver, that it can still support all of its subscribers.
If any of the API versions subscribed to has been removed then installation
will be vetoed until all the subscriber drivers have been updated to use
the newer versions of the APIs exported by the newer providing driver.

Miscellaneous
=============

For convenience the source repository includes some other scripts:

kdfiles.py
----------

This generates two files called kdfiles32.txt and kdfiles64.txt which can
be used as map files for the .kdfiles WinDBG command.

sdv.py
------

This runs Static Driver Verifier on the source.

clean.py
--------

This removes any files not checked into the repository and not covered by
the .gitignore file.

get_xen_headers.py
------------------

This will import any necessary headers from a given tag of that Xen
repository at git://xenbits.xen.org/xen.git.