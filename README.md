freeflow
=========

A software program written in C that runs a Netflow v5 receiver and parses/sends data to a Splunk HTTP Event Collector (HEC) in a compact .csv format.  This was developed as a way of ingesting Netflow into Splunk in a more economical way (~25% of the license demand) than Splunk Stream.

Requirements
------------

* This was developed and tested on CentOS 7.  I make no guarantees about performance on other distros.
* Requires openssl-devel to compile.

Compiling and Installing
------------------------

GCC needs to be installed.  Only standard libraries, plus openssl-devel are required to compile.  Run the following commands:

    make
    make install


Running
-------

    $ /opt/freeflow/bin/freeflow -c /opt/freeflow/etc/freeflow.cfg
    $ /opt/freeflow/bin/freeflow -c /opt/freeflow/etc/freeflow.cfg -d  (to enable debug logging)

or, to run as a service run the following commands:

    sudo systemctl daemon-reload
    sudo systemctl enable freeflow
    sudo systemctl start freeflow

Building an RPM
---------------

YMMV, but these are the steps I use to build RPM files in a test environment where the rpmbuild base directory is /root/rpmbuild and C-Freeflow was cloned into /root.  Adjust accordingly for your environment.

    tar -czvf /root/rpmbuild/SOURCES/freeflow-1.0.tar.gz -C /root/ C-Freeflow/ --transform s/C-Freeflow/freeflow-1.0/
    rpmbuild -ba /root/C-Freeflow/rpmbuild/freeflow.spec
    
License
-------
Apache License Version 2.0

Author Information
------------------

Christopher Costa, christopher.costa@gmail.com
