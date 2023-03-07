import angr
import re

def function_stack_usage(asm):
    '''
    识别对栈指针的压栈操作进而完成对函数栈深度的识别
    '''
    arch_bytes=4 # 32位有效
    for op in asm.raw_result:
        if type(op) != angr.analyses.disassembly.Instruction:
            continue
        code = op.opcode
        if code.opcode_string == 'push':
            # push {rx,....,ry}
            regs = op.insn.op_str
            size = 1
            for c in regs:
                if c == ',':
                    size = size + 1
            return size * arch_bytes
        if code.opcode_string == 'sub':
            # sub sp, fp or sp, #0x<NUM>
            regs = op.insn.op_str
            res = [int(s,16) for s in re.findall(r'sp, \w+, #0x([\w|\d]+)', regs)]
            if len(res) != 1:
                continue
            return res[0] + arch_bytes
    print('can\'t find stack info in for this function')
    print(asm.render())
    return 0

def import_elf(file_name: str):
    '''
    LOAD ELF
    '''
    prj = angr.Project(file_name)
    cfg = prj.analyses.CFG()
    return prj, cfg

def get_max_stack_depth(node, call_stack, call_graph, stack_usage_list):
    '''
    递归遍历查找最大深度的函数栈

    - node 当前函数ID
    - call_stack 当前调用栈, 首先由于是深度优先所以最底层的函数放在最前面
    - call_graph angr提供的函数调用关系有向图
    - stack_usage_list 有向图价值表(由function_stack_usage()提前计算)
    '''
    obj = call_graph.adj.get(node)
    self_stack = stack_usage_list[node]
    stack = self_stack
    cpy_call_stack = call_stack.copy()
    max_call_stack = cpy_call_stack
    max_node = 0
    for next_node in obj.keys():
        if next_node == 0:
            break
        new_stack, call_stack = get_max_stack_depth(next_node, call_stack, call_graph, stack_usage_list)
        new_stack = new_stack + self_stack
        if new_stack > stack:
            stack = new_stack
            max_node = next_node
            max_call_stack = call_stack

    if max_node > 0:
        cpy_call_stack = max_call_stack
    cpy_call_stack.append(node)
    return stack, cpy_call_stack


if __name__ == '__main__':
    prj,cfg = import_elf('./examples/arm.out')

    entry = prj.entry
    cfg.functions[entry]
    stack_usage={}

    # query any functions stack usage
    for index in cfg.functions:
        f = cfg.functions[index]
        asm = prj.analyses.Disassembly(f)
        stack_usage[index] = function_stack_usage(asm)

    print("print functions stack usage:")
    for i in stack_usage:
        func_name = cfg.functions[i].name
        stack = stack_usage[i]
        if stack is not None:
            print('\t%s : %d' % (func_name, stack))

    # find adj
    callgraph = cfg.functions.callgraph

    # find entry function
    main_id = None
    for id in cfg.functions:
        f = cfg.functions[id]
        if f.name == 'main':
            main_id = id
            break

    stack_depth, call_stack = get_max_stack_depth(main_id, [], callgraph, stack_usage)
    print("Max stack size: %s" % stack_depth)
    for x in call_stack:
        print("[%s]" % cfg.functions[x].name, end="->")
