from copy import copy, deepcopy
import matplotlib.pyplot as plt
import csv
from numpy import log2
from dataclasses import dataclass
import pandas as pd

fieldnames = ['entries', 'size', 'ecd_time', 'ecd_size', 'query_gen_time', 'answer_gen_time', 'answer_get_time', "tot_time", 'query_size', 'answer_size']

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
def read_csv(path : str):
    df = pd.read_csv(path)
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
    groups = read_csv("pir.csv")

    for group in groups:
        fig, axs = plt.subplots(3)
        for i, metric in enumerate(["Time(s)", "Memory(GB)", "Network(MB)"]):
            labels = []
            typ = ""
            if group.typ == "by entries":
                typ = "Record size(B)"
            else:
                typ = "Entries in DB (log2)"

            for label, record in group.records.items():
                axs[i].plot(record.x, record.metrics[metric])
                labels.append(label)
            axs[i].legend(labels)

            axs[i].xaxis.set_label_text(typ)
            axs[i].yaxis.set_label_text(metric)
        fig.suptitle(group.typ)
        plt.savefig(f"{group.typ}.png", format="png")








