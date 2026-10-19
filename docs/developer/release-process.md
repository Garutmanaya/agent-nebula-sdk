# Release Process

The SDK is published to public PyPI by GitHub Actions when a `v*` Git tag is pushed.
The workflow is defined in [`.github/workflows/publish-pypi.yml`](../../.github/workflows/publish-pypi.yml).

## Before tagging

1. Complete local tests and acceptance checks; the publishing workflow does not run pytest.
2. Review public API changes, documentation, standards mapping, and semantic versioning impact.
3. Ensure the publishing workflow is present on the branch being tagged.
4. Confirm the PyPI Trusted Publisher matches the GitHub repository, workflow filename,
   and `pypi` environment. No PyPI API token is required.

## Publish

Create and push an immutable release tag, for example:

```bash
git tag v5.0.1
git push origin v5.0.1
```

The workflow derives the package version from the tag (`v5.0.1` becomes `5.0.1`),
updates `pyproject.toml` **inside the runner only**, builds wheel and source distributions,
and publishes them to PyPI using OIDC Trusted Publishing. It does not commit the version
change back to the repository.

Check the GitHub Actions run and the published release at
<https://pypi.org/project/agent-nebula-sdk/>.

## After publishing

- Keep the checked-in `pyproject.toml` version aligned with the latest release when
  updating repository metadata. A tag-triggered build does not update this file in Git.
- Do not reuse a published version: PyPI does not allow replacing an existing release.
- Update changelog and migration notes as appropriate. Downstream projects should
  explicitly select the SDK release they intend to consume.
