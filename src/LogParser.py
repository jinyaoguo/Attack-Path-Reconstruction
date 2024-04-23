# 定义事件解析格式
SYSCALL_TYPE = 7
SYSCALL_DIR = 6
PROC_ID = 5
PROC_NAME = 4
TIME = 1

target_type = [
    "read",
    "write",
    "readv",
    "writev",
    "execve",
    "fork",
    "clone",
    "sendto",
    "recvfrom",
    "recvmsg",
    "sendmsg",
    "accept",
    "fcntl",
    "rename",
    "renameat2",
]
event_list = []


def extract_fd(log: str):
    fd = log[log.index("fd=") :].split(" ")[0]
    path = ""
    for index, char in enumerate(fd):
        if char == ">":
            path = fd[index + 1 : len(fd) - 1]
            if "(" in path:
                path = path[path.index("(") + 1 : len(path) - 1]
            break
    return path


def get_entity_type(entity):
    if len(entity.split(".")) >= 6 and len(entity.split(":")) >= 2:
        return "network"
    if "/" in entity:
        return "file"
    else:
        return "process"


def extract_res(log: str):
    res = log[log.index("res=") + 4 :].split(" ")[0]
    if res[0] != "-":
        if "(" in res:
            res = res.split("(")[0]
        return res
    return "-1"


# filter out irrelevant events and generate event list
def log_filter(log_path, output_path):
    try:
        with open(log_path) as f:
            primary_log = f.readlines()
            f.close()
    except:
        print("Error when read log files")
        return

    # filter out target syscall event

    primary_log = list(
        filter(lambda x: x.split(" ")[SYSCALL_TYPE] in target_type, primary_log)
    )

    event_num = 0
    for index, value in enumerate(primary_log):
        syscall_type = value.split(" ")[SYSCALL_TYPE]
        syscall_dir = value.split(" ")[SYSCALL_DIR]
        proc_id = value.split(" ")[PROC_ID]
        if syscall_dir == ">":
            couple = [value.split(" ")]
            i = 0
            while True:
                i += 1
                new_type = primary_log[index + i].split(" ")[SYSCALL_TYPE]
                new_dir = primary_log[index + i].split(" ")[SYSCALL_DIR]
                new_proc = primary_log[index + i].split(" ")[PROC_ID]
                if (
                    (new_type == syscall_type)
                    and (new_dir == "<")
                    and syscall_type == "execve"
                ):
                    couple.append(primary_log[index + i].split(" "))
                    break
                if (
                    (new_type == syscall_type)
                    and (new_dir == "<")
                    and new_proc == proc_id
                ):
                    couple.append(primary_log[index + i].split(" "))
                    break
                if i >= 20:
                    break
            # get the couple of an event
            if len(couple) == 2:
                if syscall_type == "accept":
                    continue
                res = extract_res(" ".join(couple[1]))
                res_num = int(res)
                # delete event with response number less than 0
                if res_num < 0:
                    # del primary_log[index]
                    # del primary_log[index+i]
                    continue

                # generate event list
                # Network / file to process
                if syscall_type in ["read", "readv", "recvfrom", "recvmsg", "fcntl"]:
                    source = extract_fd(" ".join(couple[0]))
                    if source == "":
                        continue
                    if (
                        syscall_type in ["recvfrom", "recvmsg", "fcntl"]
                        and get_entity_type(source) != "network"
                    ):
                        continue
                    destination = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    size = res
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            source,
                            destination,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    continue

                # Process to F/N
                if syscall_type in ["write", "writev", "sendto", "sendmsg"]:
                    source = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    destination = extract_fd(" ".join(couple[0]))
                    if destination == "":
                        continue
                    if (
                        syscall_type in ["sendto", "sendmsg"]
                        and get_entity_type(destination) != "network"
                    ):
                        continue
                    size = res
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            source,
                            destination,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    continue

                # if syscall_type in ['recvmsg']:
                #     source = extract_fd(' '.join(couple[0]))
                #     if source == '':
                #         continue
                #     destination = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                #     size = res
                #     start_time = couple[0][TIME]
                #     end_time = couple[1][TIME]
                #     if source != '':
                #         event_num += 1
                #         event_list.append([event_num, source, destination, syscall_type, size, start_time, end_time])
                #     continue

                if syscall_type in ["execve"]:
                    source = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    destination = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    tmp_log = " ".join(couple[0])
                    filename = tmp_log[tmp_log.index("filename=") + 9 :].split(" ")[0]
                    if "(" in filename:
                        filename = filename[filename.index("(") + 1 : -1]
                    size = 0
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]

                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            source,
                            destination,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            filename,
                            destination,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    # event_num += 1
                    # event_list.append([event_num, destination, source, syscall_type, size, start_time, end_time])
                    continue

                if syscall_type in ["clone"]:
                    source = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    tmp_log = " ".join(couple[1])
                    des = tmp_log[tmp_log.index("res=") + 4 :].split(" ")[0]
                    destination = des.split("(")[0] + des.split("(")[1][:-1]
                    size = 0
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    if destination != "":
                        event_num += 1
                        event_list.append(
                            [
                                event_num,
                                source,
                                destination,
                                syscall_type,
                                size,
                                start_time,
                                end_time,
                            ]
                        )
                    continue

                # Process to N & N to Process
                if syscall_type in ["accept"]:
                    process = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    network = extract_fd(" ".join(couple[0]))
                    if network == "":
                        continue
                    size = res
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]

                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            process,
                            network,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            network,
                            process,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    continue

                if syscall_type in ["rename", "renameat2"]:
                    process = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    log = " ".join(couple[1])
                    old_path = log[
                        log.index("oldpath=")
                        + 8 : log.index(" ", log.index("oldpath="))
                    ]
                    if "(" in old_path:
                        old_path = old_path[old_path.index("(") + 1 : len(old_path) - 1]
                    new_path = log[
                        log.index("newpath=")
                        + 8 : log.index(" ", log.index("newpath="))
                    ]
                    if "(" in new_path:
                        new_path = new_path[new_path.index("(") + 1 : len(new_path) - 1]
                    if old_path[-1] == ")":
                        old_path = old_path[old_path.index("(") + 1 : -1]
                    if new_path[-1] == ")":
                        new_path = new_path[new_path.index("(") + 1 : -1]
                    size = res
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            old_path,
                            process,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    event_num += 1
                    event_list.append(
                        [
                            event_num,
                            process,
                            new_path,
                            syscall_type,
                            size,
                            start_time,
                            end_time,
                        ]
                    )
                    continue

    try:
        with open(output_path, "w") as f:
            for line in event_list:
                line = str(line).replace("'", "").replace(",", "")[1:-1]
                f.write(line + "\n")
            f.close()
    except Exception as e:
        print(e)
        raise


if __name__ == "__main__":
    SYSCALL_TYPE = 5
    SYSCALL_DIR = 4
    PROC_ID = 3
    PROC_NAME = 2
    TIME = 1
    LOG_PATH = "../input/test.log"
    EVENT_PATH = "../input/after_filter.log"
    log_filter(LOG_PATH, EVENT_PATH)
