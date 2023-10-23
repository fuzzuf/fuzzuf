/*===- StandaloneFuzzTargetMain.c - standalone main() for fuzz targets. ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This main() function can be linked to a fuzz target (i.e. a library
// that exports LLVMFuzzerTestOneInput() and possibly LLVMFuzzerInitialize())
// instead of libFuzzer. This main() function will not perform any fuzzing
// but will simply feed all input files one by one to the fuzz target.
//
// Use this file to provide reproducers for bugs when linking against libFuzzer
// or other fuzzing engine is undesirable.
//===----------------------------------------------------------------------===*/
#include <iostream>
#include <chrono>
#include <memory>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
__attribute__((weak)) extern int LLVMFuzzerInitialize(int *argc, char ***argv);
int main(int argc, char **argv) {
  fprintf(stderr, "StandaloneFuzzTargetMain: running %d inputs\n", argc - 1);
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  for (int i = 1; i < argc; i++) {
    fprintf(stderr, "Running: %s\n", argv[i]);
    FILE *f = fopen(argv[i], "r");
    assert(f);
    fseek(f, 0, SEEK_END);
    long int len = ftell(f);
    assert( len >= 0 );
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char*)malloc( (size_t)len );
    size_t n_read = fread(buf, 1, (size_t)len, f);
    fclose(f);
    assert(n_read == (size_t)len);
    LLVMFuzzerTestOneInput(buf, (size_t)len);
    free(buf);
    fprintf(stderr, "Done:    %s: (%zd bytes)\n", argv[i], n_read);
  }
}
