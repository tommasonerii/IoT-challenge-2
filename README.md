# IoT Challenge 2

Challenge solution repository for an Internet of Things assignment with two deliverables:

- **Part 1**: trace analysis on `A.pcapng` and `B.pcapng` using Wireshark, TShark, and Python
- **Part 2**: an energy comparison exercise between CoAP and MQTT for a smart-building scenario

## What This Repo Does

This project answers the challenge questions, checks protocol exchanges at packet level, and produces the final LaTeX reports.

In short, it is used to:

- inspect CoAP, MQTT, and MQTT-SN traffic
- compute CQ1 to CQ8 from the captures
- solve the Part 2 energy exercise
- build the final `Challenge.pdf` and `Exercise.pdf`

## Project Structure

- `part1/scripts/` - self-contained Python scripts for the Part 1 questions
- `part1/answers/` - short text answers for Part 1
- `part1/filters/` - display filters used during the analysis
- `part1/figures/` - plots and figures included in the report
- `part1/report/Challenge.tex` - LaTeX source for the Part 1 report
- `part1/requirements.txt` - Python dependencies for the analysis scripts
- `part2/report/Exercise.tex` - LaTeX source for the Part 2 report
- `README.md` - project overview

## Requirements

- Python 3.10 or newer
- Wireshark or TShark available in `PATH`
- A LaTeX distribution for compiling the reports

Python packages used by the analysis scripts are listed in `part1/requirements.txt`:

- `pyshark`
- `pandas`
- `matplotlib`
- `seaborn`
- `scapy`

## How It Works

### Part 1

Each script in `part1/scripts/` focuses on one challenge question or a small group of related questions. The scripts are designed to be reproducible and use protocol fields, message directions, and capture-level checks instead of relying only on broad filters.

### Part 2

`part2/report/Exercise.tex` contains the full energy-consumption solution for the smart-building scenario, with the CoAP and MQTT calculations written in LaTeX.

### Final Deliverables

Compile the two LaTeX sources to generate the submission PDFs:

- `part1/report/Challenge.tex` -> `Challenge.pdf`
- `part2/report/Exercise.tex` -> `Exercise.pdf`

## Notes

- Malformed packets are ignored in the Part 1 analysis.
- The capture files are expected by the scripts through their built-in search logic, so the repository can still be used if the traces are placed in the usual challenge folder structure.
- CQ8 also generates the figure used to compare local broker usage across the two captures.
