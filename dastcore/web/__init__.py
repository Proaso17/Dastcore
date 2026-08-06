"""Local web dashboard for dastcore (`dastcore serve`).

A single-operator, localhost-first UI over the existing scan engine: launch a
scan from a form, watch live progress, and browse a persistent history of past
runs with their findings. It reuses the CLI's scan pipeline verbatim and stores
results in SQLite so history survives restarts. Runs where you run the CLI, so
it keeps network reach to internal/staging targets and keeps intrusive traffic
on the operator's machine.
"""
