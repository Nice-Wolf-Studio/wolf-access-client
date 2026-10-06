# wolf-access-client

The Python client library for **wolf-access**, the Nice-Wolf-Studio authorization service.
A service embeds it to ask wolf-access whether the person behind a call may see or change one of
the service's resources, and to filter lists and search results down to what that person may see.

## Install

Install it by release tag, the same way as
[gateway-client](https://github.com/Nice-Wolf-Studio/gateway-client). No token or other credential
is needed:

```bash
pip install "git+https://github.com/Nice-Wolf-Studio/wolf-access-client@vX.Y.Z"
```

Replace `vX.Y.Z` with a release tag from this repo.

## What is public and what is not

- This repo is public. It holds the client code only: **no secrets and no data**.
- The wolf-access service and its specification are in a private repo. The client talks to a
  running wolf-access service with a per-service credential that the service supplies at run
  time; no credential is ever committed here.
