/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

int main( int argc, char *argv[] ) {
  if( argc < 2 ) abort();
  FILE *fd = fopen( argv[ 1 ], "r" );
  const int a = getc( fd );
  const int b = getc( fd );
  const int c = getc( fd );

  if( a < 0 || b < 0 || c < 0 ) {
    abort();
  }
  exit( 0 );
  if( a == b && b == c ) {
    abort();
  } 
  exit(0);
}

