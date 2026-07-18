# Agent Nebula SDK Source Documentation Standard

Every source module, public class, public method, and public function must explain its responsibility, relevant standards, operational assumptions, and failure behavior. Security-sensitive implementation branches must also include inline comments where the reason for validation order or rejection is not obvious from the code.

## Required source structure

1. Module docstring describing purpose and standards.
2. Explicit constants and immutable policy models.
3. Public contracts before concrete implementations.
4. Focused methods with one responsibility.
5. Stable SDK exceptions at protocol boundaries.
6. Product persistence and business policy supplied only through ports.

## Definition of done

`make verify` must pass formatting, linting, strict typing, documentation audit, tests, coverage, and compilation before a step may be tagged.
