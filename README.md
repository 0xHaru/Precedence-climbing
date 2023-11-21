# Precedence climbing

This program aims to provide a simple example of parsing expressions
by precedence climbing.

## Compilation and usage

```
make
./calc
```

## Example

```
> 2 + 3 * 4
(2 + (3 * 4)) = 14.00

> (2 - 3) * 4
((2 - 3) * 4) = -4.00

> -2 ^ 2
-(2 ^ 2) = -4.00

> 2 ^ 2 ^ 3
(2 ^ (2 ^ 3)) = 256.00

> (10 * (350 + -25)) / 2
((10 * (350 + -25)) / 2) = 1625.00

> 100 + -2 ^ -(2 + 1) * 25
(100 + (-(2 ^ -(2 + 1)) * 25)) = 96.88
```

## References

-   [Parsing expressions by precedence climbing](https://eli.thegreenplace.net/2012/08/02/parsing-expressions-by-precedence-climbing)
-   [Operator-precedence parser](https://en.wikipedia.org/wiki/Operator-precedence_parser)

## License

This source code is licensed under the GNU General Public License
v3.0.
