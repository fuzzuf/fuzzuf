# MOpt

## What is MOpt

[MOpt-AFL](https://github.com/puppet-meteor/MOpt-AFL) is an example implementation for MOpt[^usenix19] paper.
It tries to optimize the selection of mutation operators to find more interesting inputs by generating probability distributions from *particles* calculated with its original heuristics inspired by PSO (Particle Swarm Optimization).


## CLI Usage

fuzzuf MOpt provides the same CLI interface with fuzzuf AFL:

```bash
fuzzuf mopt --in_dir=path/to/initial/seeds/ -- path/to/PUT @@
```

The MOpt CLI has the same global options as the fuzzuf AFL CLI. Refer to the [AFL/algorithm_en.md](/docs/algorithms/afl/algorithm_en.md) for the available options. The MOpt CLI does not have specific local options.



## Algorithm Overview
Original MOpt-AFL consists of 4 modules:
- PSO Initialization Module
- Pilot Fuzzing Module
- Core Fuzzing Module
- PSO Updating Module

Workflows of these modules are similar to PSO algorithm: Initialize particles in PSO Initialization Module, evaluate and update local best in Pilot/Core Fuzzing Module and then update global best in PSO Updating Module.
fuzzuf MOpt implements same algorithm with some additional HierarFlow `MOptUpdate`.

For pacemaker mode in MOpt-AFL, fuzzuf MOpt has HierarFlow `CheckPacemakerThreshold` inserted before `ApplyDetMuts`.
Pacemaker will skip determined mutations like bitflips to speed up fuzzing process under some conditions.

### PSO Initialization Module
MOpt intializes swarms and local/global bests in MOptOptimizer constructor. The number of dimension is equal to the number of mutation operations; `fuzzuf::mutator::NUM_CASE`.

### Pilot/Core Fuzzing Module
There are two different functions for pilot/core fuzzing module in original implementation of MOpt-AFL, however, MOptState has boolean member (`bool pacemaker_mode`) inside to switch state for pilot/core fuzzing module. In MOpt-related flow, they will check/update the value according to their state.
HierarFlow `MOptUpdate` will update swarm index and calculate local best. MOpt-AFL do that at the end of pilot/core fuzzing module.

### PSO Updating Module
PSO Updating Module originally update global best; probability distribution. fuzzuf MOpt implements `MOptUpdate` for updating global best as well.
