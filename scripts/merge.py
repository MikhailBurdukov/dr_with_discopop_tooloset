import xml.etree.ElementTree as ET
import subprocess
from xml.dom import minidom

class Node:
    def __init__(self):
        self.id = 0
        self.startsAtLine = ""
        self.endsAtLine = ""
        self.bb_id = -1
        self.readDataSize = 0
        self.writeDataSize = 0
        self.instructionsCount = 0
        self.readPhaseLines = 0
        self.successors = []
        self.callsNode = []
        self.instructionLines = []
    
    def to_etree(self):
        root = ET.Element('Node', id=str(self.id), name="", startsAtLine = self.startsAtLine,  endsAtLine=self.endsAtLine)
        
        et = ET.Element('BasicBlockID')
        et.text=self.bb_id[0]
        root.append(et)

        et = ET.Element('readDataSize')
        et.text=str(self.readDataSize)
        root.append(et)

        et = ET.Element('writeDataSize')
        bb.text=str(self.writeDataSize)
        et.append(et)
        
        et = ET.Element('writeDataSize')
        et.text=str(self.writeDataSize)
        root.append(et)

        et = ET.Element('instructionsCount')
        et.text=str(self.instructionsCount)
        root.append(et)
        
        et = ET.Element('instructionLines', count=str(len(self.instructionLines)))
        et.text =  ",".join(str(x) for x in self.instructionLines)
        root.append(et)

        return root

cus_path = './cus.xml'
cfg_path = './cfg.xml'
module_mapper_path = 'modules.log'

    

def get_modules(path):
    result = {}
    with open(path) as file:
        lines = [line.rstrip() for line in file]
    for line in lines[2:]:
        lst = line.replace(" ", "").split(',')
        if(len(lst)>=10):
            id = int(lst[0].encode('utf-8'))
            start =  int(lst[2], 16)
            end =   int(lst[3], 16)
            offset = int(lst[5], 16)
            name = lst[9]
            result[id] = [start,end,name,offset]
            print(str(id) + " : " + str(result[id]) )
    return result

cus = ET.parse(cus_path).getroot()
cfg = ET.parse(cfg_path).getroot()
module_mapper = get_modules(module_mapper_path)
file_cache = {}
result_xml = ET.Element('Nodes')

bbs = {}
print(module_mapper)

def get_from_file_cache(path):
    if path not in file_cache:
        file_cache[path] = len(file_cache) + 1
    return file_cache [path]
        

def resolve_addresses(instrs):
    all_lines = []
    min_max_line = []
    max = 0
    min = int("0xffffffffffffffff", 16)
    max_res = ""
    min_res = ""
    for x in instrs:
        instr = int(x[1:-1],16)
        module_id =  [id for id in module_mapper if module_mapper[id][0] <= instr and module_mapper[id][1] >= instr][0]
        # print("instr " + hex(instr) + " module base : " + hex(module_mapper[module_id][0]))
        offset = instr - module_mapper[module_id][0] + module_mapper[module_id][3]
        # print(hex(offset))
        result = subprocess.run(["addr2line", "-e", module_mapper[module_id][2], hex(offset)], stdout = subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if (result.stderr == None):
            continue
        path = result.stdout
        path = path.split(" ")[0].split(':')
        file_id = get_from_file_cache(path[0])
        # print(file_id)
        if path[1][-1] == '\n':
            path[1] = path[1][:-1]
        line = int(path[1])
        all_lines.append(str(file_id)+":"+path[1])
        
        if(instr > max):
            max_res = all_lines[-1]
            max = instr
        if(instr < min):
            min_res = all_lines[-1]
            min = instr
        
        
    return list(set(all_lines)) , max_res , min_res, file_id


for bb in cfg:
    end   = int(bb.attrib['endaddr'], 16)
    start = int(bb.attrib['startsaddr'], 16)
    id    = bb.attrib['id']
    bbs[id] = [start, end, bb]
    # print(bb.attrib['startsaddr'][2::].encode('utf-8').hex())

print(bbs)

nodes = dict()
cus_iterator = dict()
# Constructing Result xml file
print(len(cus))
for cu in cus:
    print(cu.attrib)
    id = int(cu.attrib['id'])
    
    all_instrs = cu[0].text.split(",")
    instr = int(cu[0].text.split(",")[0][1:-1], 16)
    
    bb_id = [ bb for bb in bbs if bbs[bb][0] <= instr and bbs[bb][1] >= instr]
   
    list_of_source_files, max_res, min_res, file_id = resolve_addresses(all_instrs)
    
    if file_id not in cus_iterator:
        cus_iterator[file_id] = 1
    else:
        cus_iterator[file_id] += 1 
    nodes[id] = Node()
    
    nodes[id].id =  str(file_id)+":" + str(cus_iterator[file_id])
    nodes[id].startsAtLine = min_res
    nodes[id].endsAtLine = max_res
    nodes[id].readDataSize = int(cu[2].text)
    nodes[id].writeDataSize = int(cu[3].text)
    nodes[id].bb_id = bb_id
    nodes[id].instructionsCount = len(all_instrs)
    nodes[id].readPhaseLines = 0
    nodes[id].successors = cu[1].text.split(",")
    nodes[id].instructionLines = list_of_source_files
    print(id)

print(nodes)
for id in nodes:
    result = []
    for s in nodes[id].successors:
        if int(s) in nodes: 
            result.append(nodes[int(s)].id)
    nodes[id].successors = result
    
root = ET.Element("Nodes")

print(nodes)
for id in nodes:
    n = nodes[id].to_etree()
    print(n)
    root.append(n)


with open('result.xml','w') as fd:
    fd.write(minidom.parseString((ET.tostring(root).decode())).toprettyxml(indent="   "))

    
    


