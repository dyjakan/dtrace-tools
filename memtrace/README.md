DTrace Memory Tracer
====================

This is a DTrace tool which aims to create an ltrace compatible output for 
heap management functions which can be visualised by villoc.

Usage
-----

```shell
$ sudo ./memtrace.d -c <app> | ./villoc.py - out.html
```

