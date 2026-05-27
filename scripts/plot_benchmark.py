#!/usr/bin/env python3
"""Plot prove+execute benchmark comparison for swiyu-jwt and swiyu-mdoc circuits."""

import csv
import glob
import os
import sys

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


def load_latest_benchmark(directory):
    pattern = os.path.join(directory, "benchmark-*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No benchmark CSV files found in {directory}")
    path = files[-1]
    print(f"Loading {path}", file=sys.stderr)

    x, y = [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            x.append(int(row["max_length"]) / 1000)
            y.append(float(row["nargo_execute"]) + float(row["bb_prove"]))
    return x, y


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    jwt_x, jwt_y = load_latest_benchmark(
        os.path.join(repo_root, "circuits/jwt-swiyu")
    )
    mdoc_x, mdoc_y = load_latest_benchmark(
        os.path.join(repo_root, "circuits/mdoc-swiyu")
    )

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(jwt_x, jwt_y, marker="o", label="swiyu-jwt")
    ax.plot(mdoc_x, mdoc_y, marker="s", label="swiyu-mdoc")

    ax.set_yscale("log")
    fmt = FuncFormatter(lambda v, _: f"{int(v)}" if v >= 1 else f"{v:g}")
    ax.yaxis.set_major_formatter(fmt)
    ax.yaxis.set_minor_formatter(fmt)
    ax.set_xlabel("Credential max. length (kB)")
    ax.set_ylabel("Time (s) — prove + execute")
    ax.set_title("ZK Circuit Benchmark: prove + execute time")
    ax.legend()
    ax.grid(True, which="both", alpha=0.3)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved to {out_path}")


if __name__ == "__main__":
    main()
