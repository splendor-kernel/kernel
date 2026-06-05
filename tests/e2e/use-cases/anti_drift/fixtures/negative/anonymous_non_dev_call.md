# Bad request fixture

In a fleet non-dev request the scenario sends credential: null and relies on the
daemon accepting anonymous access.

POST /runs
