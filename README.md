freeflow
=========

A software program written in C that runs a Netflow v5 receive and parses/sends to a Splunk HTTP Event Collector (HEC) in a compact .csv format.  This was developed as a way of ingesting Netflow into Splunk in a more economical way (i.e. less license) than Splunk Stream's JSON encoding..

Requirements
------------

* This was developed and tested on CentOS 7.  I make no guarantees about performance on other distros.
* Currently it only supports HTTP, and not HTTPS enabled HEC.

Compiling
---------

GCC needs to be installed.  Only standard libraries are required.

    gcc freeflow.c logger.c queue.c config.c socket.c worker.c -o freeflow.out -lrt

Running
-------

    $ freeflow.out -c freeflow.cfg
    $ freeflow.out -c freeflow.cfg -d    (to enable debug logging)

Author Information
------------------

Christopher Costa, christopher.costa@gmail.com
