import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mangopanel.agent import Agent
from mangopanel.config import load_config


def main():
    parser = argparse.ArgumentParser(description="Run the MangoPanel development node agent.")
    parser.add_argument("--once", action="store_true", help="Process one queued job and exit.")
    parser.add_argument("--apply-all", action="store_true", help="Regenerate and apply every hosting account stack.")
    parser.add_argument("--down-all", action="store_true", help="Stop every generated hosting account stack.")
    parser.add_argument("--limit", type=int, default=25, help="Maximum jobs to process in batch mode.")
    args = parser.parse_args()

    agent = Agent(load_config())
    if args.down_all:
        for result in agent.down_all_accounts():
            print(result)
    elif args.apply_all:
        for result in agent.apply_all_accounts():
            print(result)
    elif args.once:
        print(agent.run_once())
    else:
        for result in agent.run_all(limit=args.limit):
            print(result)


if __name__ == "__main__":
    main()
