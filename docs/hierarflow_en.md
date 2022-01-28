# Implementation of HierarFlow

## HierarFlow's Tree Structure

As stated in README, a HierarFlow constructs a tree structure. For example, [AFL implementation](/README.md#example-afl-in-hierarflow) would form the following tree:

![afl_hierarflow_tree.png](/docs/resources/img/afl_hierarflow_tree.png)

## `HardLink()`-ing a node

[In an AFL example](/README.md#example-afl-in-hierarflow), we can see that some nodes are used with `HardLink()` member function. This function generates a fresh copy of that node which is independent from its origin.  
Since each node represents a single node in a tree, a copy must be generated if a node originating from the same routine appears multiple times (otherwise a node may have multiple parents and a tree structure collapses).

## Summary of HierarFlow

HierarFlow consist of several C\+\+ classes and template classes. This section briefly summarizes some of the most essential ones.  

### `HierarFlowNode<IReturn(IArgs...), O, IS_REGULAR>`

A primitive class describing a node in a tree structure, that depends on several template parameters. It is a wrapper of `HierarFlowNodeImpl`, which is explained later.

### `HierarFlowRoutine<I, O>`

A template class which describes a routine (procedure) executed by its derived nodes. 

### `HierarFlowPath`

A class describing a parent-child relationship of succeeding nodes, that is made by an operator `<<`. The path (i.e. parent-child relationship) defines the order of execution.

### `HierarFlowChildren`

A class that describes a set of sibling nodes having the same parent node, that are coupled together by an operator `||`.

### `HierarFlowCallee<IReturn(IArgs...)>`

A template class which handles a node as an object called by its parent.

### `HierarFlowCaller<OReturn(OArgs...)>`

A template class which handles a node as an object that calls its chlidren (thus, a companion of `HierarFlowCallee`).

### `HierarFlowNodeImpl<I, O, IS_REGULAR>`

A template class wrapped by `HierarFlowNode` shown above. It represents an entity of the node and is coupled with a routine that corresponds to as a class member `routine`.

Usually, users do not have to care about this class when using HierarFlow and should keep using a wraper class `HierarFlowNode`.  
The exception is when they are using `UnwrapCurrentLinkedNodeRef()` function, usually in a routine that is going to create an irregular node.

## HierarFlow in detail

A building block in HierarFlow is a user-implemented class derived from the template class `HierarFlowRoutine`. In fuzzuf, those routines become templates for block generation.  
Users who want to add a new fuzzer to fuzzuf should implement a new class deriving `HierarFlowRoutine` as a procedure linked to each block dividing a fuzzing loop.  
Each building block is generated as a node in a tree structure and connected with operators to make a fuzzing loop as a structured flow.

Further, since blocks include an executor primitive responsible for PUT execution, a fuzzer can support multi-platform by replacing those relevant parts.  
Specifically, users should define a new class deriving the `Executor` class, then implement required member functions per platform and virtual functions such as `virtual void Run(...)`.

### `HierarFlowNode<IReturn(IArgs...), O, IS_REGULAR>`

This primitive class describes a node in a tree structure. It depends on template parameters `IReturn`, `IArgs...` (parameter pack), `O', and `IS_REGULAR`, whereas:

- `IReturn`: a return type from an own node to a parent node  
- `IArgs...`: a parameter pack containing argument types passed from a parent node an own node  
    - The type `IReturn(IArgs...)` is internally aliased as `I = IReturn(IArgs...)`. 
- `O': a type also can be described as `OReturn(OArgs...)` where
    - `OReturn`: a return type from a child node to an own node
    - `OArgs...`: a parameter pack containing argument types passed from an own node to a child node  
- `IS_REGULAR`: a boolean telling if the node is a regular HierarFlow node  (handled as a HierarFlowNode if true)

For the sake of brevity, the class will be denoted as `HierarFlowNode<I, O, IS_REGULAR>` in this document.  
We will explain HierarFlowNodeImpl, a wrapper of another class, later.

A template parameter `IS_REGULAR` represents if its child nodes are called regularly or not. If false (called irregular node), the routine linked to the node is expected to call them non-sequentially (e.g., pick and call one of the child nodes randomly, then ignore the rest).  
Users do not have to specify such regularity explicitly. Instead, they should use `CreateNode<R>()` or `CreateIrregularNode<R>()` accordingly.  
Note, such regularity is just a visual difference, i.e., both regular and irregular nodes are handled the samely inside. To make it easier to notice their regularity, they are differentiated for users (not for HierarFlow nor fuzzuf) to make it easier to see their regularity.

In contrast, an irregular node (`IS_REGULAR=false`) may handle its succeeding nodes differently.  
On this occasion, the function may get a reference to the `HierarFlowNodeImpl` object currently linked through the `UnwrapCurrentLinkedNodeRef()` function to modify the order of successor executions directly.  
It is also possible to override the virtual function `CallSuccessors()` itself to control each child node's execution freely.

### `HierarFlowRoutine<I, O>`

This class describes a routine (procedure) executed by its derived nodes. Like `HierarFlowNode`, it is a template class depending on `I` and `O`. 

The user mainly implements derivatives of this class for their new fuzzer as needed. The users can create a node from each routine with the function `Create[Irregular]Node<R>()` where `R` represents a routine class implemented.  
This class must override and implement `operator() (IArgs args...)` to describe what the routine should perform when called.

### `HierarFlowPath`

This class describes a parent-child relationship of succeeding nodes made by an operator `<<`. The path (i.e., parent-child relationship) defines the order of execution.  
Users should beware that the parent-side should transfer the control to the child-side (e.g., by calling `GoToDefaultNext()`) for the routines linked to the nodes connected by `<<`, when the former finishes its duty before it returns.

### `HierarFlowChildren`

This class describes a set of sibling nodes with the same parent node, coupled with the `||` operator.

The user who implements a fuzzing loop can transfer the control from the current node to the next one after being transferred from its parent (by calling `GoToDefaultNext()` from each routine, for example) to execute each of sibling nodes in the order as denoted.  
Alternatively, by using `GoToParent`, the child can transfer the control back to the parent without executing the rest of the sibling nodes.

### `HierarFlowCallee<IReturn(IArgs...)>`

This template class handles a node as an object called by its parent.

The class holds the information of its caller (i.e., parent) as a pointer `HierarFlowCaller<I> *parent`.

### `HierarFlowCaller<OReturn(OArgs...)>`

This template class handles a node as an object that calls its children (thus, a companion of `HierarFlowCallee`).

Similar to `HierarFlowCallee`, it has a member variable `OReturn resp_val`, which holds a return value from its child nodes (n.b. there is only one return value even there are multiple child nodes).

### `HierarFlowNodeImpl<I, O, IS_REGULAR>`

This template class is wrapped by `HierarFlowNode` explained above. It represents an entity of the node and is coupled with a routine that corresponds to a class member `routine`.

`HierarFlowNode` holds a pointer to this class as a `std::shared_ptr` named `impl`. 

To ensure (and force) the safe use of the `HierarFlowNodeImpl` object via a shared pointer, users should always use a wrapper class `HierarFlowNode` instead, except for the case when using the `HierarFlowRoutine::UnwrapCurrentLinkedNodeRef` function. 

Also, this class derives template classes `HierarFlowCallee<IReturn(IArgs...)>` and `HierarFlowCaller<OReturn(OArgs...)>`. 

![hierarflownode.png](/docs/resources/img/hierarflownode.png)

As described in the above diagram, a node (`HierarFlowNode`) simultaneously has attributes of **a child of its parent** and **a parent of its child** as an internal structure (`HierarFlowNodeImpl`). Although there are exceptions (i.e., a root node, leaf nodes), consider only ordinary nodes here.  
The child node represents the caller of the parent node, and the parent node represents the caller of the child node.

Note, the node's `IReturn` and `IArgs...` types are the same as its parent's `OReturn` and `OArgs...`. Thus, the node's `I = IReturn(IArgs...)` type is equal to its parent's `O = OReturn(OArgs...)` type.

## Internals of HierarFlow

When a HierarFlow code is evaluated as a fuzzing loop, the internal processes are as follows:

1. Users defining a new fuzzing loop create a node with `CreateNode<R>()` or `CreateIrregularNode<R>()` from derivatives of `HierarFlowRoutine` implemented by them, then connect them by operators `<<`, `[]`, and `||` (also with parentheses) to define the flow.

1. Define a member function `OneLoop()` which calls a root node through `operator()`.

1. Call `OneLoop()` via `fuzzuf` CLI. The function is called inside the while-loop to fuzz the PUT continuously.

1. A routine's `operator()` assigned to each node executes its procedure, then calls its child nodes by `CallSuccessors(args...)` with appropriate arguments provided. Note, child nodes are actually called in `runAllChildren()` function internally. Also, beware that the child nodes owning the same parent have the same parameters to be called.

1. Each node gets a reference to its child node `succ` sequentially (as defined in HierarFlow) in a while-loop, then calls `HierarFlowNodeImpl::operator()(IArgs... args)`.

1. In `HierarFlowNodeImpl::operator()`, a function `SetParentResponseValueRef()` lets a member variable `parent_response_ref` reference to its parent node's `HierarFlowCaller::resp_val`. This is possible since `HierarFlowNodeImpl` derives both `HierarFlowCallee` and `HierarFlowCaller`.

1. `HierarFlowNodeImpl::operator()` eventually calls `(*routine)(std::forward<IArgs>(args)...)` to call `operator()`s of each routine deriving a class `HierarFlowRoutine`.

1. Each routine's `operator()` linked to a child node calls its child node (thus a grandchild of the original parent node) via `CallSuccessors()` if it exists.

1. If a child node wants to transfer the control to its sibling, it calls `GoToDefaultNext()` to obtain a reference to a derivative of `HierarFlowCallee`, that is going to be returned to its parent's `runAllChildren()` as a variable `next_succ_ref`. If there is no child node left, a while-loop is terminated as it returns `std::nullopt`. In addition, an iteration of child nodes can be interrupted in the middle (i.e., terminates while-loop) by calling `GoToParent()` in one of the child nodes.

1. A parent node that completed an iteration of child nodes may alter its procedure according to the value of `resp_val` returned through `CallSuccessors()` if needed.

1. Repeat `GoToDefaultNext()` or `GoToParent()` as appropriate at the nodes transitioned, and eventually call such functions in the root node to finish one single fuzzing loop.

