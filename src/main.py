import BackPropagate
import LogParser
from argparse import ArgumentParser
import os


def get_args():
    ag = ArgumentParser()
    ag.add_argument("-n", "--name", help="log name")
    ag.add_argument("-l", "--log", help="log file path")
    ag.add_argument("-e", "--poi", help="poi event file path")
    ag.add_argument("-r", "--high_rp", help="high risk process file path")
    ag.add_argument("-o", "--output", help="output directory path")
    ag.add_argument("-s", "--size", help="detection size")

    return ag.parse_args()


def main():
    args = get_args()
    log_name = args.name
    log_path = args.log
    poi_event = args.poi
    high_rp = args.high_rp
    output_dir = f"{args.output}/{log_name}"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    event_path = f"{output_dir}/{log_name}.log"
    graph_path = f"{output_dir}/{log_name}"
    detection_size = int(args.size)

    LogParser.log_filter(log_path, event_path)
    print("filter success!")
    back_analyser = BackPropagate.BackwardPropagate(
        event_path, graph_path, poi_event, detection_size, high_rp
    )
    back_analyser.run()


if __name__ == "__main__":
    main()
