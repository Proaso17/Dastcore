"""Cloud control-plane + self-hosted runner (the SaaS foundation).

Because dastcore does active, intrusive scanning it must reach the target's
network — so a multi-tenant cloud can't scan a customer's internal/staging boxes
directly. The model instead is a **control-plane** (this package's FastAPI app)
that stores projects, queues scan jobs and keeps results, plus **runners** —
lightweight agents deployed inside the customer's network that claim queued jobs,
run the scan locally with the normal engine, and push results back.

This is a foundation: multi-tenant projects + API keys, the runner claim/result
protocol, and job storage. Billing, orgs/roles, and a hosted UI are out of scope.
"""
