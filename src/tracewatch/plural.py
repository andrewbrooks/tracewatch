"""Counts in prose: "1 connection", "2 connections" (never "1 connection(s)")."""


def pl(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"
