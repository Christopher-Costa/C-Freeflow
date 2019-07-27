freeflow
=========

A software program written in C that runs a Netflow v5 receiver and parses/sends data to a Splunk HTTP Event Collector (HEC) in a compact .csv format.  This was developed as a way of ingesting Netflow into Splunk in a more economical way (~25% of the license demand) than Splunk Stream.

Requirements
------------

* This was developed and tested on CentOS 7.  I make no guarantees about performance on other distros.
* Requires openssl-devel to compile.

Compiling
---------

GCC needs to be installed.  Only standard libraries, plus openssl-devel are required to compile.

    gcc src/freeflow.c src/logger.c src/queue.c src/config.c src/session.c src/worker.c src/splunk.c -o bin/freeflow -lrt -lssl -lcrypto -Ilib

Running
-------

    $ bin/freeflow -c etc/freeflow.cfg
    $ bin/freeflow -c ect/freeflow.cfg -d  (to enable debug logging)

Author Information
------------------

Christopher Costa, christopher.costa@gmail.com
