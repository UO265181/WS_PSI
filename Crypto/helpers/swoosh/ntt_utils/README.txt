README
======

This directory contains code adapted from the `py-fhe` project by Saroja Erabelli.

Original project:
https://github.com/sarojaerabelli/py-fhe

`py-fhe` is a Python 3 library for fully homomorphic encryption. It includes
implementations of the BFV and CKKS cryptosystems, as well as bootstrapping for CKKS.

In this project, parts of the NTT/FTT-related logic were taken as a reference and
adapted to the needs of the SWOOSH backend. The resulting code is not a direct use of
`py-fhe` as a full dependency, but a local adaptation of some of its ideas and components.

The original `py-fhe` project is distributed under the MIT License:

MIT License

Copyright (c) 2021 Saroja Erabelli

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.