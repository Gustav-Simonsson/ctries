
ctries
====
C implementation of concurrent tries with non-blocking snapshots

<a name='introduction'>

Introduction
------------

This is an experimental, incomplete implementation of the ctrie data structure.
In it's current state it serves as an exercise for the author to learn C and is
not useful as a ready-to-use data structure yet. Hopefully it will
evolve into something complete and stable enough for usage in other programs!

<a name='features'>

Features
--------

  * Keys in form of 32 or 64-bit words
  * Insert, update, lookup and deletion of keys

TODO
--------

  * TODO: Correct compression and contraction during deletion
  * TODO: Change test malloc/free to proper memory management
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

