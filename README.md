An Extension of BasicPOS for the Weak Memory Model 
=====================================================

In this project, we extend the BasicPOS algorithm to weak memory programs by implementing
it on top of C11Tester, the popular weak memory concurrency testing framework. We evaluate the BasicPOS for weak memory algorithm on C11Tester benchmarks and compare the performance with C11Tester and the PCT for weak memory algorithm. Our results show that BasicPOS for weak memory detects bugs more frequently than C11Tester. However, PCTWM outperforms it in the majority of the benchmarks. This motivates extending the POS algorithm to weak memory models.


C11Tester
--------------
C11Tester is a testing tool for C11/C++11 which randomly explores the
behaviors of code under the C/C++ memory model.

C11Tester is constructed as a dynamically-linked shared library which
implements the C and C++ atomic types and portions of the other thread-support
libraries of C/C++ (e.g., std::atomic, std::mutex, etc.).

C11Tester compiles on Linux.  Instrumenting programs requires using
an LLVM pass.  It likely can be ported to other \*NIX flavors.


Getting Started with C11Tester
---------------

C11Tester is available in the following vagrant repository

     https://doi.org/10.1145/


Useful Options for C11Tester
--------------

`-v`

  > Verbose: show all executions and not just buggy ones.

`-x num`

  > Specify the number number of executions to run.


Running BasicPOS for weak memory and Benchmarks
--------------------------------

1. Clone this repository in the above mentioned C11Tester's vagrant box.

```
git clone https://github.com/r-gheda/c11tester/
```

2. Make 

```
cd c11tester
make
```

3. Follow the instructions in the README of the 'c11tester-benchmarks;' directory to run the C11Testerbenchmarks.

4. For running your own code, use the script in the 'test' directory of this repository.

Note that the test programs should be compiled against C11Tester's shared library
(libmodel.so).  Then the shared library must be made available to the
dynamic linker, using the `LD_LIBRARY_PATH` environment variable, for
instance.


Execution Traces and Buggy Executions
--------------------------

For more information on C11Tester execution traces and the summary statistics of the executions, refer to https://github.com/c11tester/c11tester/blob/master/README.md



C11Tester's Copyright
---------

Copyright &copy; 2013 and 2019 Regents of the University of California. All rights reserved.

C11Tester is distributed under the GPL v2. See the LICENSE file for details.



References
----------

[1] Luo, W., Demsky, B.: C11tester: a race detector for c/c++ atomics. In: Proceedings of the
26th ACM International Conference on Architectural Support for Programming Languages and
Operating Systems, pp. 630–646 (2021)

[2] Yuan, X., Yang, J., Gu, R.: Partial order aware concurrency sampling. In: Computer Aided
Verification: 30th International Conference, CAV 2018, Held as Part of the Federated Logic
Conference, FloC 2018, Oxford, UK, July 14-17, 2018, Proceedings, Part II 30, pp. 317–335
(2018)

[3] Gao, M., Chakraborty, S., Ozkan, B.K.: Probabilistic concurrency testing for weak memory
programs. In: Proceedings of the 28th ACM International Conference on Architectural Support
for Programming Languages and Operating Systems, Volume 2, pp. 603–616 (2023)
