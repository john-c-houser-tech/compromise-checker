"""Makes one PDF, in a process of its own: HTML on standard input, the PDF on standard output.
A report's text may be a compromised host's, and WeasyPrint can use unbounded time and memory on
it, or crash outright (with no fonts on the machine, it segfaults). So this process is limited, and
can't leave a core file, which would hold the report in plain. Nothing is fetched while it runs.

Run by checker.report.pdf_from_html, by file name, so that it imports nothing of the tool."""

import resource
import sys

EXIT_NO_LIBRARY = 3
EXIT_FAILED = 4


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    memory = int(sys.argv[1])
    seconds = int(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    html = sys.stdin.buffer.read().decode("utf-8", "backslashreplace")
    try:
        from weasyprint import HTML
        from weasyprint.urls import URLFetcher
    except (ImportError, OSError):  # OSError: its native libraries aren't there
        return EXIT_NO_LIBRARY

    class NoFetching(URLFetcher):
        def fetch(self, url, headers=None):
            raise ValueError("a report fetches nothing")

    try:
        pdf = HTML(string=html, url_fetcher=NoFetching()).write_pdf()
    except Exception:  # noqa: BLE001 - its message may quote a host's text, so only the status goes
        return EXIT_FAILED
    sys.stdout.buffer.write(pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
