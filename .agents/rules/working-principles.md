# Working principles

How we work on any change here, taken from what has worked on phiward. The ideas owe a debt to
[andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills).

## Ask before you guess

A guard that rests on a wrong guess protects nothing. Write down what you take for granted
(which version of Claude Code, which platform, what a setting means) and check it, in the docs
or with a test. If a request has two readings, name both and ask which one is meant.

## The smallest change that does the job

Each mechanism in a guard is one more thing that can be wrong. Before you add a check, see
whether a mechanism can go instead: in this project that has closed more holes than new
checks did. Add no option, abstraction or case that nobody asked for.

## Leave the rest alone

A diff that touches only what the task needs is one a reviewer can read in full. Keep the style
of the code around you, do not tidy unrelated code, and remove only what your own change left
unused. Say what else you noticed; do not fix it in the same change.

## A goal you can test

"Fixed" means a test that failed now passes. Before the work, write the steps and, for each,
how you will know it is done: a red test, a check that passes, a document that matches the code.
Then work until each check passes, and say plainly what was not checked.
