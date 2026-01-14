# Contributing

Thanks for helping improve leaksniff.

## Development

```bash
pnpm install
pnpm run dev -- .
pnpm run build
pnpm run lint
pnpm test
```

## Release checklist

1) Update version in `package.json` and `CHANGELOG.md`.
2) `pnpm run clean && pnpm run build`
3) `pnpm run lint && pnpm test`
4) `npm pack --dry-run`
5) `npm publish`
