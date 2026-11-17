# Reporting a vulnerability

phiward keeps protected health information (PHI), and the credentials that would reach it, out of
what an AI coding agent sends to its model provider. If you find a way for protected data or a
credential to reach the agent, or for a guard to be turned off without the operator, please
report it privately:

- On GitHub: the repository's **Security** tab, **Report a vulnerability**.
- Do not open a public issue, and do not put the details in a commit or a pull request, until a fix
  is released.

In your report, use made-up data only (for example a file named `FAKE-PT-0001`), never real
patient data. Say what you ran, what you expected and what happened.

The known limits are stated in [docs/threat-model.md](docs/threat-model.md): a limit listed there
is known, but a better fix is still welcome.

Supported: the latest release. phiward is a beta; fixes go into the next release.
