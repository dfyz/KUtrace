#!/usr/bin/env python3
# Regenerate the device-IRQ part of kutrace_control_names_linux_grace.h from
# /proc/interrupts on the machine being traced.
#
# The arm64 KUtrace patch records device interrupts as
#   KUTRACE_IRQ + (Linux virq % 236)
# (see kutrace_irq_nr() in include/linux/kutrace.h), because 236..255 are
# reserved for the timer, IPIs and bottom halves. On a GB300 tray there are
# several hundred MSI/LPI virqs, so some numbers collide; colliding names are
# joined with "/".
#
# usage: gen_irqnames_from_proc.py [/proc/interrupts] kutrace_control_names_linux_grace.h

import collections
import re
import sys

LIMIT = 236
BEGIN = "  // IRQNAMES_BEGIN\n"
END = "  // IRQNAMES_END\n"


def read_irqs(path):
    names = collections.defaultdict(list)
    with open(path) as f:
        header = f.readline().split()
        ncpus = len(header)
        for line in f:
            fields = line.split()
            if not fields or not re.fullmatch(r"\d+:", fields[0]):
                continue  # IPIn:, Err:, etc. are not device IRQs
            virq = int(fields[0][:-1])
            rest = fields[1 + ncpus:]
            # rest is e.g. ["GICv3", "27", "Level", "arch_timer"] or
            # ["ITS-PCI-MSIX-0009:01:00.0", "0", "Edge", "mlx5_comp0@pci:0009:01:00.0"]
            name = rest[-1] if rest else "irq%d" % virq
            if "arch_timer" in name:
                continue  # traced as 236 local_timer_vector by the timer hook
            names[virq % LIMIT].append(re.sub(r'["\\]', "_", name)[:40])
    return names


def main():
    if len(sys.argv) == 2:
        proc, header = "/proc/interrupts", sys.argv[1]
    else:
        proc, header = sys.argv[1], sys.argv[2]
    names = read_irqs(proc)
    rows = []
    for num in sorted(names):
        uniq = list(dict.fromkeys(names[num]))
        label = "/".join(uniq) if len(uniq) <= 3 else "/".join(uniq[:3]) + "/+%d" % (len(uniq) - 3)
        rows.append('  {%d, "%s"},\n' % (num, label))
    text = open(header).read()
    start = text.index(BEGIN) + len(BEGIN)
    stop = text.index(END)
    open(header, "w").write(text[:start] + "".join(rows) + text[stop:])
    print("wrote %d IRQ names into %s" % (len(rows), header))


if __name__ == "__main__":
    main()
