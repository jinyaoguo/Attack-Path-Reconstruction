from graphviz import Digraph
from collections import defaultdict
import time
import math
import numpy as np
from sklearn.cluster import KMeans
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis


class Graph:
    INDEX = 0
    SRC = 1
    DST = 2
    TYPE = 3
    SIZE = 4
    START_TIME = 5
    END_TIME = 6
    SIZE_W = 7
    TIME_W = 8
    STRUC_W = 9
    FINAL_W = 10

    def __init__(self, entity_list: list, event_list: list):
        self.entity_reputation = {}
        self.entity_in_edge_dict = {}
        self.entity_out_edge_dict = {}
        self.entity_list = entity_list
        self.event_list = event_list
        self.__get_in_out_edge_of_entity()
        for entity in entity_list:
            self.entity_reputation[entity] = 0

    def set_graph(self, entity_list: list, event_list: list):
        self.entity_list = entity_list
        self.event_list = event_list
        self.__get_in_out_edge_of_entity()
        for entity in entity_list:
            self.entity_reputation[entity] = 0

    @staticmethod
    def get_entity_shape(entity):
        if len(entity.split(".")) >= 4 and len(entity.split(":")) >= 2:
            return "parallelogram"
        if "/" in entity:
            return "ellipse"
        else:
            return "square"

    def generate_graph(self, output_path: str, view: bool, info=False):
        """
        generate graph with Digraph
        :param output_path: the name of the graph
        :param view: generate image if True (cost a lot of time) or just write the src to a dot file if False.
        :param info:
        :return:
        """
        dot = Digraph()
        for index, entity in enumerate(self.entity_list):
            dot.node(str(index + 1), label=entity, shape=self.get_entity_shape(entity))
        if info:
            for event in self.event_list:
                dot.edge(
                    str(self.entity_list.index(event[self.SRC]) + 1),
                    str(self.entity_list.index(event[self.DST]) + 1),
                    label=event[self.INDEX] + " " + event[self.TYPE],
                )
        else:
            for event in self.event_list:
                dot.edge(
                    str(self.entity_list.index(event[self.SRC]) + 1),
                    str(self.entity_list.index(event[self.DST]) + 1),
                    label=event[self.INDEX],
                )
        if view:
            dot.render(output_path, view=False)
        else:
            try:
                with open(output_path, "w") as f:
                    for line in dot.source:
                        f.write(line)
                    f.close()
            except Exception as e:
                print(e)
                raise

    def draw_colorful_graph(
        self, output_path: str, entity_list: list, event_list: list, info=False
    ):
        dot = Digraph()
        crucial = Digraph()
        crucial.attr(color="blue")
        crucial.attr(label="Attack path")
        for index, entity in enumerate(self.entity_list):
            if entity in entity_list:
                crucial.node(
                    str(index + 1),
                    label=entity,
                    shape=self.get_entity_shape(entity),
                    color="red",
                )
            else:
                dot.node(
                    str(index + 1), label=entity, shape=self.get_entity_shape(entity)
                )
        if info:
            for event in self.event_list:
                if event[self.INDEX] in event_list:
                    crucial.edge(
                        str(self.entity_list.index(event[self.SRC]) + 1),
                        str(self.entity_list.index(event[self.DST]) + 1),
                        label=event[self.INDEX] + " " + event[self.TYPE],
                        color="red",
                        style="bold",
                    )
                else:
                    dot.edge(
                        str(self.entity_list.index(event[self.SRC]) + 1),
                        str(self.entity_list.index(event[self.DST]) + 1),
                        label=event[self.INDEX] + " " + event[self.TYPE],
                    )
        else:
            for event in self.event_list:
                dot.edge(
                    str(self.entity_list.index(event[self.SRC]) + 1),
                    str(self.entity_list.index(event[self.DST]) + 1),
                    label=event[self.INDEX],
                )
        dot.subgraph(crucial)
        dot.render(output_path, view=True)

    def __get_in_out_edge_of_entity(self):
        """
        get incoming and outgoing edge of all entities, store in dict
        generate entity_in_edge_dict and entity_out_edge_dict
        :return:
        """
        for entity in self.entity_list:
            in_edge = []
            out_edge = []
            for event in self.event_list:
                if event[self.SRC] == entity:
                    out_edge.append(event)
                if event[self.DST] == entity:
                    in_edge.append(event)
            self.entity_in_edge_dict[entity] = in_edge
            self.entity_out_edge_dict[entity] = out_edge

    def get_incoming_edge_dict(self):
        return self.entity_in_edge_dict

    def get_outgoing_edge_dict(self):
        return self.entity_out_edge_dict

    def set_reputation(self, entity: str, reputation: float):
        assert entity in self.entity_reputation.keys()
        self.entity_reputation[entity] = reputation

    def get_reputation(self, entity: str):
        assert entity in self.entity_reputation.keys()
        return self.entity_reputation[entity]

    def sort_reputation(self, reverse=True):
        """
        sort reputation dict,
        decrease order if reverse=True(default)
        increase order if reverse=False
        :return: sorted list
        """
        return sorted(
            self.entity_reputation.items(), key=lambda x: x[1], reverse=reverse
        )


class BackwardPropagate:
    """
    Identify critical edges and attack entries from given log files.
    """

    time_limit = 60

    def __init__(
        self,
        log_path: str,
        output_path: str,
        poi_event: str,
        detection_size=0,
        high_reputation="",
        poi_time="",
    ):
        """

        :param log_path: path of original log file
        :param output_path: the directory to store the output file
        :param poi_event: Point-Of-Interest event to be investigated
        :param detection_size: the size of poi event
        :param high_reputation: entities with high_reputation
        """
        self.start_time = time.time()
        self.output_path = output_path
        self.poi_event = poi_event
        self.detection_size = detection_size
        self.high_reputation = [high_reputation]
        self.original_graph = Graph([], [])
        self.backward_graph = None
        self.merged_backward_graph = None

        # generate original graph
        try:
            with open(log_path) as f:
                original_log_list = f.read().splitlines()
                f.close()
        except Exception as e:
            print(e)
            raise

        if poi_time == "":
            self.poi_time = 0
            for event in original_log_list:
                event = event.split(" ")
                if (
                    event[self.original_graph.DST] == self.poi_event
                    and float(event[self.original_graph.END_TIME][3:]) > self.poi_time
                ):
                    self.poi_time = float(event[self.original_graph.END_TIME][3:])
        else:
            if len(poi_time) > 16:
                self.poi_time = float(poi_time[3:])
            else:
                self.poi_time = float(poi_time)

        original_entity_list = []
        original_event_list = []
        for index, event in enumerate(original_log_list):
            event = event.split(" ")
            if float(event[self.original_graph.END_TIME][3:]) > self.poi_time:
                break

            original_event_list.append(event)
            if event[self.original_graph.SRC] not in original_entity_list:
                original_entity_list.append(event[self.original_graph.SRC])
            if event[self.original_graph.DST] not in original_entity_list:
                original_entity_list.append(event[self.original_graph.DST])

        self.original_graph.set_graph(original_entity_list, original_event_list)

    def run(self):
        print("finish init, time cost: ", time.time() - self.start_time)
        self.backward_graph = self.backward_analysis(self.original_graph)
        print("finish backward analysis, time cost: ", time.time() - self.start_time)
        self.merged_backward_graph = self.edge_merge(self.backward_graph)
        print("finish edge merge, time cost: ", time.time() - self.start_time)
        self.compute_amount_weight(self.merged_backward_graph)
        self.compute_time_weight(self.merged_backward_graph)
        self.compute_struct_weight(self.merged_backward_graph)
        # self.compute_file_weight(self.merged_backward_graph)
        self.normalize_weight_by_out_edges(self.merged_backward_graph)
        self.compute_final_wight(self.merged_backward_graph)
        print("finish weight compute, time cost: ", time.time() - self.start_time)
        self.entity_impact_backpropagation(self.merged_backward_graph)
        res = self.get_candidate_entry_point(self.merged_backward_graph)
        starts = []
        print(
            "Please set interested entry points to conduct forward analysis. Set the first 3 entities as default"
        )
        print("Input 'Enter' to continue")
        arr = input()
        if arr == "":
            for candidates in res:
                for candidate in list(candidates.keys())[:3]:
                    starts.append(candidate)
        else:
            starts = arr.split(" ")
        final_graph = self.combine_backward_forward_for_given_starts(
            starts, self.merged_backward_graph
        )
        print("finish weight compute, time cost: ", time.time() - self.start_time)
        self.get_attack_path(final_graph, starts)

    @staticmethod
    def get_entity_type(entity):
        if len(entity.split(".")) >= 4 and len(entity.split(":")) >= 2:
            return "network"
        if "/" in entity:
            return "file"
        else:
            return "process"

    def backward_analysis(self, graph: Graph):
        """
        identify poi_time, generate original backward dependency graph.
        :return: backward dependency graph based on self.poi_event
        """
        entity_list = [self.poi_event]
        event_list = []
        last_entity = ""
        index = 0

        # get poi_event
        for event in graph.event_list:
            if (
                event[graph.DST] == self.poi_event
                and float(event[graph.END_TIME][3:]) == self.poi_time
                and event not in event_list
            ):
                event_list.append(event)
                new_entity = event[graph.SRC]
                if new_entity not in entity_list:
                    entity_list.append(new_entity)

        start_time = time.time()
        accessed_entity = []
        while index < len(event_list) and time.time() - start_time < self.time_limit:
            event_cur = event_list[index]
            index += 1
            if event_cur[graph.SRC] in accessed_entity:
                continue
            accessed_entity.append(event_cur[graph.SRC])
            for event in graph.get_incoming_edge_dict()[event_cur[graph.SRC]]:
                # if event not in event_list:
                if event not in event_list and float(
                    event[graph.START_TIME][3:]
                ) <= float(event_cur[graph.END_TIME][3:]):
                    event_list.append(event)
                    new_entity = event[graph.SRC]
                    if new_entity not in entity_list:
                        entity_list.append(new_entity)

        backward_graph = Graph(entity_list, event_list)
        backward_graph.generate_graph(self.output_path + "_BackTrack.dot", view=False)
        return backward_graph

    @staticmethod
    def time_threshold_check(event1: list, event2: list, graph: Graph):
        """
        compare the end_time of event1 and start_time of event2
        :param graph: provide the index
        :param event1:
        :param event2:
        :return: True is event1 is earlier than event2
        """
        if (float(event1[graph.END_TIME]) + 10) >= float(event2[graph.START_TIME]):
            return True
        else:
            return False

    @staticmethod
    def find_start_end_time(event1: list, event2: list, graph: Graph):
        """
        get the earlier start_time and later end_time of event1 and event2
        :param graph: provide the index
        :param event1:
        :param event2:
        :return:
        """
        start_time = event1[graph.START_TIME]
        if int(event1[graph.START_TIME].split(".")[1]) > int(
            event2[graph.START_TIME].split(".")[1]
        ):
            start_time = event2[graph.START_TIME]

        if int(event1[graph.END_TIME].split(".")[0]) < int(
            event2[graph.END_TIME].split(".")[0]
        ):
            end_time = event2[graph.END_TIME]
            return start_time, end_time
        if int(event1[graph.END_TIME].split(".")[0]) > int(
            event2[graph.END_TIME].split(".")[0]
        ):
            end_time = event1[graph.END_TIME]
            return start_time, end_time
        if int(event1[graph.END_TIME].split(".")[1]) < int(
            event2[graph.END_TIME].split(".")[1]
        ):
            end_time = event2[graph.END_TIME]
        else:
            end_time = event1[graph.END_TIME]
        return start_time, end_time

    def edge_merge(self, graph: Graph):
        """
        merges the edges between two nodes if the time differences of these edges are smaller than a given threshold
        :param graph: the graph need to be merged.
        :return: merged graph
        """
        stacks = defaultdict(list)
        log_final = {}
        edge_list = graph.event_list
        entity_list = graph.entity_list
        # sort by start time
        edge_list.sort(key=lambda x: (int(x[graph.START_TIME].split(".")[0])))

        for event in edge_list:
            sys_call = event[graph.TYPE]
            src = event[graph.SRC]
            dst = event[graph.DST]
            index = event[graph.INDEX]
            if len(stacks[(src, dst, sys_call)]) == 0:
                stacks[(src, dst, sys_call)].append(event)
                log_final[index] = event
            else:
                candidate_log = stacks[(src, dst, sys_call)].pop(-1)
                if self.time_threshold_check(candidate_log, event, graph):
                    start_time, end_time = self.find_start_end_time(
                        candidate_log, event, graph
                    )
                    candidate_log[graph.START_TIME] = start_time
                    candidate_log[graph.END_TIME] = end_time
                    candidate_log[graph.SIZE] = str(
                        int(candidate_log[graph.SIZE]) + int(event[graph.SIZE])
                    )
                    stacks[(src, dst, sys_call)].append(candidate_log)
                    log_final[candidate_log[0]] = candidate_log

        merged_graph = Graph(entity_list, list(log_final.values()))
        merged_graph.generate_graph(self.output_path + "_Merge.dot", view=False)
        return merged_graph

    def compute_amount_weight(self, graph: Graph):
        """
        compute amount weight and store as the 8th element in the event (list)
        :param graph: the graph to be computed
        :return:
        """
        target_list = [self.detection_size]
        for event in graph.event_list:
            if (
                event[graph.TYPE] == "execve"
                and self.get_entity_type(event[graph.SRC]) == "file"
                and len(graph.get_incoming_edge_dict()[event[graph.SRC]]) != 0
            ):
                max_size = 0
                for event in graph.get_incoming_edge_dict()[event[graph.SRC]]:
                    # if int(event[graph.SIZE]) > max_size:
                    #     max_size = int(event[graph.SIZE])
                    print(event)
                    max_size += int(event[graph.SIZE])
                if max_size not in target_list:
                    target_list.append(max_size)
        print(target_list)
        alpha = 0.0001
        for event in graph.event_list:
            max_weight = 0
            for target_size in target_list:
                size_weight = 1 / (abs(target_size - int(event[graph.SIZE])) + alpha)
                if size_weight > max_weight:
                    max_weight = size_weight
            event.append(max_weight)

    def compute_time_weight(self, graph: Graph):
        """
        compute time weight and store as the 9th element in the event (list)
        :param graph: the graph to be computed
        :return:
        """
        for event in graph.event_list:
            if float(event[graph.END_TIME][3:]) == self.poi_time:
                mini_diff = 1.0e-10
                time_weight = math.log(1.0 + 1.0 / abs(mini_diff))
                event.append(time_weight)
            else:
                time_weight = math.log(
                    1.0 + 1.0 / abs(self.poi_time - float(event[graph.END_TIME][3:])),
                    math.e,
                )
                event.append(time_weight)

    def compute_struct_weight(self, graph: Graph):
        """
        compute time structure and store as the 10th element in the event (list)
        :param graph: the graph to be computed
        :return:
        """
        for event in graph.event_list:
            entity = event[graph.DST]
            if entity == self.poi_event:
                concentration_weight = len(graph.event_list) * 1.0
            else:
                concentration_weight = len(
                    graph.get_outgoing_edge_dict()[entity]
                ) / len(graph.get_incoming_edge_dict()[entity])
            event.append(concentration_weight)

    @staticmethod
    def normalize_weight_by_out_edges(graph: Graph):
        """
        normalize weight to [0-1] based on the outgoing edge sets
        :param graph: the graph to be normalized
        :return:
        """
        assert len(graph.event_list[0]) == graph.FINAL_W

        for outgoing in graph.get_outgoing_edge_dict().values():
            size_total_weight = 0
            time_total_weight = 0
            struct_total_weight = 0
            file_total_weight = 0
            for out_edge in outgoing:
                size_total_weight += out_edge[graph.SIZE_W]
                time_total_weight += out_edge[graph.TIME_W]
                struct_total_weight += out_edge[graph.STRUC_W]
            for out_edge in outgoing:
                out_edge[graph.SIZE_W] = (
                    out_edge[graph.SIZE_W] / size_total_weight * len(outgoing)
                )
                out_edge[graph.TIME_W] = (
                    out_edge[graph.TIME_W] / time_total_weight * len(outgoing)
                )
                if struct_total_weight != 0:
                    out_edge[graph.STRUC_W] = (
                        out_edge[graph.STRUC_W] / struct_total_weight * len(outgoing)
                    )

    @staticmethod
    def cluster_edges(weight_matrix, clustering_method):
        """
        separate edges into two groups.
        :param weight_matrix: weight matrix of edge set.
        :param clustering_method: the cluster algorithm, "k-means" or "k-means++"
        :return:
        """
        cluster_result = None
        if clustering_method == "kmeans++":
            kmeans_model = KMeans(n_clusters=2, init="k-means++", n_init=1).fit(
                weight_matrix
            )
            cluster_result = kmeans_model.labels_
        elif clustering_method == "multi_kmeans++":
            kmeans_model = KMeans(n_clusters=2, init="k-means++", n_init=20).fit(
                weight_matrix
            )
            cluster_result = kmeans_model.labels_
        else:
            raise Exception("Do not support the clustering method " + clustering_method)
        return cluster_result

    def adjust_projection_direction(
        self, graph: Graph, cluster_dict: dict, final_weight
    ):
        """
        make sure critical edge set has larger weight
        :param graph:
        :param cluster_dict: cluster result.
        :param final_weight:
        :return:
        """
        seed_edge_in_g0 = False
        seed_edge_in_g1 = False
        final_weight_g0 = []
        final_weight_g1 = []
        for index, edge in enumerate(graph.event_list):
            if edge[graph.DST] == self.poi_event:
                if cluster_dict[edge[graph.INDEX]] == "0":
                    seed_edge_in_g0 = True
                if cluster_dict[edge[graph.INDEX]] == "1":
                    seed_edge_in_g1 = True
            if cluster_dict[edge[graph.INDEX]] == "0":
                final_weight_g0.append(final_weight[index])
            if cluster_dict[edge[graph.INDEX]] == "1":
                final_weight_g1.append(final_weight[index])

        mean_g0 = np.mean(np.array(final_weight_g0))
        mean_g1 = np.mean(np.array(final_weight_g1))
        if seed_edge_in_g0 and not seed_edge_in_g1:
            if mean_g0 < mean_g1:
                print("Cluster 0 has seed edges but cluster 1 hasn't.")
                final_weight *= -1
        elif seed_edge_in_g1 and not seed_edge_in_g0:
            if mean_g1 < mean_g0:
                print("Cluster 1 has seed edges but cluster 0 hasn't.")
                final_weight *= -1
        else:
            if len(final_weight_g0) < len(final_weight_g1) and mean_g0 < mean_g1:
                final_weight *= -1
            elif len(final_weight_g1) < len(final_weight_g0) and mean_g1 < mean_g0:
                final_weight *= -1

    @staticmethod
    def scale_range(numbers: np.ndarray):
        """
        scale numbers to [0,1] range.
        :param numbers: the num list
        :return:
        """
        min_value = numbers.min()
        if min_value < 0:
            for index, value in enumerate(numbers):
                numbers[index] -= min_value
            max_value = numbers.max()
            min_value = numbers.min()
        else:
            max_value = numbers.max()

        second_min = max_value
        for value in numbers:
            if value != min_value and value < second_min:
                second_min = value

        offset = second_min - min_value / 100
        print(
            "Scaling statistics --- min:",
            min_value,
            "max:",
            max_value,
            "secondMin:",
            second_min,
            "offset:",
            offset,
            "scaledMin:",
            offset / (max_value - min_value),
        )
        for index, value in enumerate(numbers):
            numbers[index] = (value - min_value + offset) / (max_value - min_value)

    def compute_final_wight(self, graph: Graph):
        """
        separate the edges into two groups, then use LDA to project the weights
        the goal is to maximize the differences between critical edges and non-critical edges
        :param graph: the graph to be computed
        :return:
        """
        weights_list = []
        for edge in graph.event_list:
            weights_list.append(edge[graph.SIZE_W : graph.STRUC_W + 1])
        weight_array = np.array(weights_list)
        cluster_result = self.cluster_edges(weight_array, "multi_kmeans++")
        cluster_dict = {}
        for i in range(0, len(cluster_result)):
            cluster_dict[graph.event_list[i][graph.INDEX]] = str(cluster_result[i])

        # print("cluster 0")
        # for edge in graph.event_list:
        #     if cluster_dict[edge[graph.INDEX]] == "0":
        #         print(edge)
        # print("\ncluster 1")
        # for edge in graph.event_list:
        #     if cluster_dict[edge[graph.INDEX]] == "1":
        #         print(edge)

        LDA = LinearDiscriminantAnalysis(n_components=1)
        LDA.fit(weight_array, cluster_result)
        final_weight = LDA.transform(weight_array).reshape(-1)
        self.adjust_projection_direction(graph, cluster_dict, final_weight)
        self.scale_range(final_weight)

        for index, edge in enumerate(graph.event_list):
            edge.append(final_weight[index])

        for out_edges in graph.get_outgoing_edge_dict().values():
            total_out_weight = 0
            for edge in out_edges:
                total_out_weight += edge[graph.FINAL_W]
            for edge in out_edges:
                edge[graph.FINAL_W] = edge[graph.FINAL_W] / total_out_weight * 0.99

    def initial_reputation(self, graph: Graph):
        """
        set the reputation of crucial entity to 1
        :param graph:
        :return:
        """
        for entity, incoming in graph.get_incoming_edge_dict().items():
            if entity in self.high_reputation:
                print(entity + " has high reputation")
                graph.set_reputation(entity, 1.0)
            elif len(incoming) == 0:
                graph.set_reputation(entity, 0.0)

    def entity_impact_backpropagation(self, graph: Graph):

        self.initial_reputation(graph)

        fluctuation = 1
        iter_time = 0

        while fluctuation >= 1.0e-13:
            cumulative_diff = 0
            iter_time += 1

            for entity, out_edges in graph.get_outgoing_edge_dict().items():
                if entity in self.high_reputation:
                    continue
                rep = 0
                for event in out_edges:
                    rep += graph.get_reputation(event[graph.DST]) * event[graph.FINAL_W]
                cumulative_diff += abs(rep - graph.get_reputation(entity))
                graph.set_reputation(entity, rep)
            fluctuation = cumulative_diff

        print(
            "After {} times iteration, the reputation of each vertex is stable".format(
                iter_time
            )
        )

    def get_candidate_entry_point(self, graph: Graph):
        """
        get candidate entry point in three types: process, ip, file
        :param graph:
        :return: [process_candidate, ip_candidate,file_candidate]
        """
        library = Library()
        process_candidate = {}
        ip_candidate = {}
        file_candidate = {}
        entity_reputation_list = graph.sort_reputation()
        for entity, reputation in entity_reputation_list:
            if len(entity.split(".")) >= 4 and len(entity.split(":")) >= 2:
                [ip1, ip2] = entity.split("->")
                if ip1.startswith("127") and ip2.startswith("127"):
                    continue
                ip_candidate[entity] = graph.get_reputation(entity)
            elif "/" in entity:
                # if entity not in libraries and len(graph.get_incoming_edge_dict()[entity]) == 0:
                #     file_candidate[entity] = graph.get_reputation(entity)
                if len(
                    graph.get_incoming_edge_dict()[entity]
                ) == 0 and not library.is_lib(entity):
                    file_candidate[entity] = graph.get_reputation(entity)
            else:
                source_ip = False
                source_process = False
                for edge in graph.get_incoming_edge_dict()[entity]:
                    node = edge[graph.SRC]
                    if len(node.split(".")) >= 4 and len(node.split(":")) >= 2:
                        source_ip = True
                        break
                    if self.get_entity_type(node) == "process":
                        source_process = True
                        break
                if not source_ip and not source_process:
                    process_candidate[entity] = graph.get_reputation(entity)

        print("=========================================================")
        for entity, reputation in ip_candidate.items():
            print(entity, reputation)
        print("=========================================================")
        for entity, reputation in file_candidate.items():
            print(entity, reputation)
        print("=========================================================")
        for entity, reputation in process_candidate.items():
            print(entity, reputation)
        print("=========================================================")
        res = [process_candidate, ip_candidate, file_candidate]
        print(
            "Entry Num: ",
            len(process_candidate) + len(ip_candidate) + len(file_candidate),
        )
        return res

    def combine_backward_forward_for_given_starts(
        self, starts: list, backward_graph: Graph
    ):
        """
        get the edges that both in backward graph and forward graph
        :param starts: the start entities to generate forward graph
        :param backward_graph:
        :return:
        """
        forward_analyser = ForwardAnalysis(self.original_graph)
        forward_graphs = forward_analyser.multiple_forward_analysis(
            starts, self.poi_time
        )
        forward_graph_edge_union = {}
        for graph in forward_graphs:
            for edge in graph.event_list:
                key = edge[0]
                if key not in forward_graph_edge_union.keys():
                    forward_graph_edge_union[key] = 0
                forward_graph_edge_union[key] += 1
        filter_edge = []
        filter_entity = []
        for event in backward_graph.event_list:
            if event[backward_graph.INDEX] in forward_graph_edge_union.keys():
                if event[backward_graph.SRC] not in filter_entity:
                    filter_entity.append(event[backward_graph.SRC])
                if event[backward_graph.DST] not in filter_entity:
                    filter_entity.append(event[backward_graph.DST])
                if event not in filter_edge:
                    filter_edge.append(event)

        # print("\n crucial entity")
        # for entity in filter_entity:
        #     print(entity)
        # print("\n crucial edge")
        # for edge in filter_edge:
        #     print(edge)

        final_graph = Graph(filter_entity, filter_edge)
        final_graph.generate_graph(
            self.output_path + "_Final.dot", view=False, info=True
        )
        return final_graph

    def get_attack_path(self, graph: Graph, entry_list: list):
        entity_dict = {self.poi_event: Node(self.poi_event, path=[self.poi_event])}

        # get POI nodes
        for event in graph.event_list:
            if event[graph.DST] == self.poi_event:
                new_entity = event[graph.SRC]
                if new_entity not in entity_dict.keys():
                    path = entity_dict[self.poi_event].path.copy()
                    path.append(new_entity)
                    entity_dict[new_entity] = Node(
                        new_entity,
                        path,
                        entity_dict[self.poi_event],
                        " ".join(event[graph.INDEX : graph.END_TIME + 1]),
                        1,
                        event[graph.FINAL_W],
                        event[graph.FINAL_W],
                    )

        index = 0
        while index < len(list(entity_dict.keys())):
            entity_cur = list(entity_dict.keys())[index]
            index += 1
            for event in graph.event_list:
                if event[graph.DST] == entity_cur:
                    new_entity = event[graph.SRC]

                    father_node = entity_dict[event[graph.DST]]
                    hop = father_node.hop + 1
                    weight = father_node.weight + event[graph.FINAL_W]
                    avg_weight = weight / hop
                    if new_entity in father_node.path:
                        continue
                    path = father_node.path.copy()
                    path.append(new_entity)
                    if new_entity not in entity_dict.keys():
                        entity_dict[new_entity] = Node(
                            new_entity,
                            path,
                            father_node,
                            " ".join(event[graph.INDEX : graph.END_TIME + 1]),
                            hop,
                            weight,
                            avg_weight,
                        )
                    elif avg_weight > entity_dict[new_entity].avg_weight:
                        entity_dict[new_entity].set(
                            path,
                            father_node,
                            " ".join(event[graph.INDEX : graph.END_TIME + 1]),
                            hop,
                            weight,
                            avg_weight,
                        )

        path_entity = {}
        path_event = {}
        for entity in entry_list:
            cur_node = entity_dict[entity]
            entity_list = [entity]
            event_list = []
            while cur_node.father is not None:
                # circle in the graph
                if cur_node.father.name in entity_list:
                    break
                event_list.append(cur_node.father_event.split(" "))
                cur_node = cur_node.father
                entity_list.append(cur_node.name)
            path_entity[entity] = entity_list
            path_event[entity] = event_list

        path_entity = dict(
            sorted(
                path_entity.items(),
                key=lambda item: entity_dict[item[0]].avg_weight,
                reverse=True,
            )
        )

        crucial_entity = []
        crucial_event = []
        count = 0
        for key in path_entity.keys():
            count += 1
            path_graph = Graph(path_entity[key], path_event[key])
            path_graph.generate_graph(
                self.output_path + "_path/" + str(count) + ".dot", view=True, info=True
            )
            for entity in path_entity[key]:
                if entity not in crucial_entity:
                    crucial_entity.append(entity)
            for event in path_event[key]:
                if event[graph.INDEX] not in crucial_event:
                    crucial_event.append(event[graph.INDEX])

        graph.draw_colorful_graph(
            self.output_path + "_Final_color.dot",
            crucial_entity,
            crucial_event,
            info=True,
        )

        print("Attack path:")
        for key, value in path_entity.items():
            print(key, value)


class Node:
    def __init__(
        self, name, path, father=None, father_event="", hop=0, weight=0, avg_weight=0
    ):
        self.name = name
        self.father = father
        self.father_event = father_event
        self.hop = hop
        self.weight = weight
        self.avg_weight = avg_weight
        self.path = path

    def set(self, path, father, father_event, hop, weight, avg_weight):
        self.father = father
        self.father_event = father_event
        self.hop = hop
        self.weight = weight
        self.avg_weight = avg_weight
        self.path = path


class ForwardAnalysis:
    def __init__(self, graph: Graph):
        self.graph = graph

    def forward_limited_by_time(self, start: str, poi_time: float):
        assert start in self.graph.entity_list

        entity_list = [start]
        edge_list = []
        for entity in entity_list:
            out_edges = self.graph.get_outgoing_edge_dict()[entity]
            for edge in out_edges:
                target = edge[self.graph.DST]
                if float(edge[self.graph.START_TIME][3:]) <= poi_time:
                    if target not in entity_list:
                        entity_list.append(target)
                    if edge not in edge_list:
                        edge_list.append(edge)
        forward_graph = Graph(entity_list, edge_list)
        return forward_graph

    def multiple_forward_analysis(self, starts: list, poi_time: float):
        graphs = []
        for start in starts:
            print("forward analyses of ", start, " finished")
            graphs.append(self.forward_limited_by_time(start, poi_time))
        return graphs


class Library:
    def __init__(self):
        self.prefix = ["/lib", "/usr/lib", "/usr/local/lib", "/lib64"]
        self.suffix = ["so", "conf", "pyc", "cnf"]

    def set_prefix(self, prefix: list):
        if prefix:
            self.prefix = prefix

    def set_suffix(self, suffix: list):
        if suffix:
            self.suffix = suffix

    def is_lib(self, name: str):
        has_prefix = False
        for prefix in self.prefix:
            if name.startswith(prefix):
                has_prefix = True
                break
        if not has_prefix:
            return False
        has_suffix = False
        file_name = name.split("/")[-1].split(".")
        file_name.reverse()
        for part in file_name:
            if part.isdigit():
                continue
            if part in self.suffix:
                has_suffix = True
            break
        return has_suffix
