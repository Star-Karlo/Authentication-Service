# Architecture documentation

These describe the whole Karlo platform, not just this service. They are
duplicated into each service repo because there is no shared repo to hold them;
when one changes, update every copy.

| | |
|---|---|
| [DATA.md](DATA.md) | Which database belongs to which service, every table and collection, and how records cross service boundaries |
| [BUSINESS.md](BUSINESS.md) | What each service decides, the state machines, and a flow traced end to end |
| [TESTING.md](TESTING.md) | What each test covers and why it exists |
| [OBSERVABILITY.md](OBSERVABILITY.md) | Logging and Fluentd, Swagger, and the linter setup |

Links pointing into another service's repository assume the
`github.com/karlo/<service>` naming. Adjust them if you publish under a
different owner.
