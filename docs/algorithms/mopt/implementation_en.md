# MOpt implementation in fuzzuf

## Reference MOpt Implementation

- Version: 2.52b
- Commit: https://github.com/puppet-meteor/MOpt-AFL/tree/a9a5dc5c0c291c1cdb09b2b7b27d7cbf1db7ce7b

## Differences from the original implementation

Since original AFL-MOpt implements their method in a weird way, fuzzuf MOpt rewrote all algorithms to reproduce original MOpt-AFL behaviour with fuzzuf architecture. Basically there is no difference between MOpt-AFL and fuzzuf MOpt.

## Added HierarFlow routines for MOpt

- MOptUpdate: updates local/global best and update the number of havoc operators found.
- CheckPacemakerThreshold: check current time to determine if they should switch to pacemaker mode or not. This HierarFlow would be callced right before ApplyDetMuts node.
- MOptHavoc/MOptSplicing: is required to change the label for displaying trying method in fuzzuf interface.