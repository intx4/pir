from copy import copy, deepcopy
import matplotlib.pyplot as plt
import csv
from numpy import log2
from dataclasses import dataclass
import pandas as pd

fieldnames = ["entries", "size", "dimentions", "N", "ecd_time", "ecd_size", "query_gen_time", "query_size", "query_size_no_evt_keys", "answer_gen_time", "answer_size", "answer_get_time", "online_time", "online_time_no_evt_keys", "baseline", "withTLS", "DL", "UL", "leakedBits", "informationBits"]

class RecordsOfInstance:
    """
    Represents records associated to a db instance.
    Type can be "by records" or "by size".
    x will be either the db sizes associated to a fixed record size or record sizes associated to a fixed db size
    metrics are the performance
    """
    def __init__(self, label : str):
        self.label = label
        self.x : [int] = []
        self.metrics : {str: []} = {'Time(s)':[], "Memory(GB)":[], "Network(MB)":[]}

    def deepcopy(self):
        r = RecordsOfInstance(self.label)
        r.metrics = deepcopy(self.metrics)
        r.x = deepcopy(self.x)
        return r


class Group:
    """
    Group records based on record size or entry size. From here we will plot performance metrics keeping on the x the record or db size and on the y a metric like time or memory
    Example:
        We can create a Group of type "by entries".
        The records in this group will be RecordsOfInstance where:
            -   label = number of entries of that db instance
            -   x = all the different record sizes tested
            -   metrics = performance in terms of different metric of this db instance as a function of x
    """
    def __init__(self, typ : str, records : [RecordsOfInstance]):
        self.records = {}
        self.typ = typ
        for record in records:
            self.records[record.label] = record.deepcopy()

def read_csv(path : str,d=2, n = 13):
    df = pd.read_csv(path)
    df = df[df['d'] == d]
    df = df[df['N'] == n]
    db_sizes = df['entries'].unique()
    record_sizes = df['size'].unique()
    records_by_entries = []
    records_by_sizes = []

    for entry in db_sizes:
        rst_df = df[df['entries'] == entry]
        rst_df.sort_values(by="size")
        records_by_entries.append(RecordsOfInstance(log2(entry)))
        for _,row in rst_df.iterrows():
            records_by_entries[-1].x.append(row["size"])
            records_by_entries[-1].metrics["Time(s)"].append(row["tot_time"])
            records_by_entries[-1].metrics["Memory(GB)"].append(row["ecd_size"]/1e9)
            records_by_entries[-1].metrics["Network(MB)"].append(row["query_size"]/1e6 + row["answer_size"]/1e6)

    for size in record_sizes:
        rst_df = df[df['size'] == size]
        rst_df.sort_values(by="entries")
        records_by_sizes.append(RecordsOfInstance(size))
        for _,row in rst_df.iterrows():
            records_by_sizes[-1].x.append(log2(row["entries"]))
            records_by_sizes[-1].metrics["Time(s)"].append(row["tot_time"])
            records_by_sizes[-1].metrics["Memory(GB)"].append(row["ecd_size"]/1e9)
            records_by_sizes[-1].metrics["Network(MB)"].append(row["query_size"]/1e6 + row["answer_size"]/1e6)

    return [Group("Evaluation with varying number of entries (log2)", records_by_entries), Group("Evaluation with record sizes (B)", records_by_sizes)]


if __name__ == "__main__":

    for d in [2,3]:
        for n in [12,13,14]:
            if d == 3 and n == 4096:
                continue

            groups = read_csv("pirGo.csv", d, n)

            for group in groups:
                fig, axs = plt.subplots(3)
                for i, metric in enumerate(["Time(s)", "Memory(GB)", "Network(MB)"]):
                    labels = []
                    typ = ""
                    if "(B)" in group.typ:
                        #x axis has the entries in db, function is determined by record size
                        typ = "Entries in DB (log2)"
                    else:
                        #x axis has the record size in B, function is determined by num of entries
                        typ = "Record size(B)"

                    for label, record in group.records.items():
                        axs[i].plot(record.x, record.metrics[metric])
                        labels.append(label)
                    axs[i].legend(labels)

                    axs[i].xaxis.set_label_text(typ)
                    axs[i].yaxis.set_label_text(metric)
                fig.suptitle(group.typ)
                plt.savefig(f"{group.typ}_dim{d}_n{n}.png", format="png")








