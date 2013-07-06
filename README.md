
ctries
====
A C implementation of concurrent tries with non-blocking snapshots

<a name='introduction'>

Introduction
------------

This is a experimental, incomplete implementation of the ctrie data structure.
In it's current state it serves more as an exercise in learning C for
the author than as a useful, ready-to-use data structure. Hopefully it will
evolve into something complete and stable enough for usage in other programs!


<a name='features'>

Features
--------

  * Insertion of keys in form of 32 or 64-bit words
  * Lookup of keys
  * TODO: Deletion of keys
  * TODO: Correct compression and contraction during deletion
  * TODO: CAS on inodes for all modifications
  * TODO: Switch CAS into GCAS to enable snapshots
  * TODO: Atomic snapshots


<a name='build'>

Build
-----
Currently the only dependency aside from GCC is the FNV hash library.
It is included in this git repo.

```sh
make compile
make run
```

Contribute
----------

Patches/forks/comments are greatly appreciated!

