#!/usr/bin/env python3

import argparse
import sys
from typing import List, Tuple

import testcases
from implementations import IMPLEMENTATIONS, Role
from interop import InteropRunner
from testcases import MEASUREMENTS, TESTCASES


def main():
    def get_args():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-d",
            "--debug",
            action="store_const",
            const=True,
            default=False,
            help="turn on debug logs",
        )
        parser.add_argument(
            "-s", "--server", help="server implementations (comma-separated)"
        )
        parser.add_argument(
            "-c", "--client", help="client implementations (comma-separated)"
        )
        parser.add_argument(
            "-t",
            "--test",
            help="test cases (comma-separatated). Valid test cases are: "
            + ", ".join([x.name() for x in TESTCASES + MEASUREMENTS]),
        )

        parser.add_argument(
            "-l",
            "--log-dir",
            help="log directory",
            default="",
        )
        parser.add_argument(
            "-f", "--save-files", help="save downloaded files if a test fails"
        )
        parser.add_argument(
            "-i", "--implementation-directory",
            help="Directory containing the implementations."
                 "This is prepended to the 'path' in the implementations.json file."
                 "Default: .",
            default='.'
        )
        parser.add_argument(
            "-j", "--json", help="output the matrix to file in json format"
        )
        parser.add_argument(
            "--venv-dir",
            help="dir to store venvs",
            default="",
        )
        parser.add_argument(
            "--testbed",
            help="Runs the measurement in testbed mode. Requires a json file with client/server information"
        )
        parser.add_argument(
            "--bandwidth",
            help="Set a link bandwidth value which will be enforced using tc. Is only set in testbed mode on the remote hosts. Set values in tc syntax, e.g. 100mbit, 1gbit"
        )

        return parser.parse_args()

    def get_impls(arg, availableImpls, role) -> List[str]:
        if not arg:
            return availableImpls
        impls = []
        for s in arg.split(","):
            if s not in availableImpls:
                sys.exit(role + " implementation " + s + " not found.")
            impls.append(s)
        return impls

    def get_tests_and_measurements(
        arg,
    ) -> Tuple[List[testcases.TestCase], List[testcases.TestCase]]:
        if arg is None:
            return TESTCASES, MEASUREMENTS
        elif arg == "onlyTests":
            return TESTCASES, []
        elif arg == "onlyMeasurements":
            return [], MEASUREMENTS
        elif not arg:
            return []
        tests = []
        measurements = []
        for t in arg.split(","):
            if t in [tc.name() for tc in TESTCASES]:
                tests += [tc for tc in TESTCASES if tc.name() == t]
            elif t in [tc.name() for tc in MEASUREMENTS]:
                measurements += [tc for tc in MEASUREMENTS if tc.name() == t]
            else:
                print(
                    (
                        "Test case {} not found.\n"
                        "Available testcases: {}\n"
                        "Available measurements: {}"
                    ).format(
                        t,
                        ", ".join([t.name() for t in TESTCASES]),
                        ", ".join([t.name() for t in MEASUREMENTS]),
                    )
                )
                sys.exit()
        return tests, measurements

    tests, measurements = get_tests_and_measurements(get_args().test)
    return InteropRunner(
        implementations=IMPLEMENTATIONS,
        implementations_directory=get_args().implementation_directory,
        servers=get_impls(get_args().server, IMPLEMENTATIONS, "Server"),
        clients=get_impls(get_args().client, IMPLEMENTATIONS, "Client"),
        tests=tests,
        measurements=measurements,
        output=get_args().json,
        debug=get_args().debug,
        log_dir=get_args().log_dir,
        save_files=get_args().save_files,
        venv_dir=get_args().venv_dir,
        testbed=get_args().testbed,
        bandwidth=get_args().bandwidth
    ).run()


if __name__ == "__main__":
    sys.exit(main())
