"""phiward: keep protected data out of what an AI coding agent's tools print.

The core is the standard library only, with no network and no telemetry. An adapter turns a tool's
hook payload into an `Action`; the dispatcher runs every enabled guard on it and returns one
`Decision`; the adapter turns that into the tool's reply.
"""

__version__ = "0.2.0b1"
