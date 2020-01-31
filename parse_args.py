#!/usr/bin/env python

"""Arguments parser demo"""

import argparse


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument("input", type=str, help="intput name")
    parser.add_argument("output", type=str, help="output name")
    parser.add_argument("--debug", action="store_true",
                        help="enable debug")

    return parser.parse_args()


def main():

    args = parse_args()

    print args.input
    print args.output
    print args.debug


if __name__ == "__main__":

    main()
