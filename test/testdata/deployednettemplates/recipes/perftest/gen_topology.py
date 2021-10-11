node_types = {"R":1, "N":3, "NPN":20}
node_size = {"R":"-c5d.4xl", "N":"-c5d.4xl", "NPN":"-c5d.4xl"}
regions = [
    "AWS-US-EAST-2"
]

f = open("topology.json", "w")
f.write("{ \"Hosts\":\n  [")

region_count = len(regions)
first = True
for  x in node_types:
    node_type = x
    node_count = node_types[x]
    region_size = node_size[x]
    for i in range(node_count):
        node_name = node_type + str(i+1)
        region = regions[i%region_count]
        if (first ):
            first = False
        else:
            f.write(",")
        f.write ("\n    {\n      \"Name\": \"" + node_name + "\",\n      \"Template\": \"" + region + region_size + "\"\n    }"  )

f.write("\n  ]\n}\n")
f.close()

