

#include "dr_api.h"
#include "cfg.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

const std::string cfg_t::TOOL_NAME = "View tool";

analysis_tool_t *
cfg_tool_create(const std::string &module_file_path, uint64_t skip_refs,
                 uint64_t sim_refs, const std::string &syntax, unsigned int verbose,
                 const std::string &alt_module_dir)
{
    return new cfg_t(module_file_path, skip_refs, sim_refs, syntax, verbose,
                      alt_module_dir);
}

cfg_t::cfg_t(const std::string &module_file_path, uint64_t skip_refs, uint64_t sim_refs,
               const std::string &syntax, unsigned int verbose,
               const std::string &alt_module_dir)
    : module_file_path_(module_file_path)
    , knob_verbose_(verbose)
    , trace_version_(-1)
    , knob_skip_refs_(skip_refs)
    , skip_refs_left_(knob_skip_refs_)
    , knob_sim_refs_(sim_refs)
    , sim_refs_left_(knob_sim_refs_)
    , timestamp_(0)
    , has_modules_(true)
{
}

std::string
cfg_t::initialize_stream(memtrace_stream_t *serial_stream)
{
    serial_stream_ = serial_stream;
    
    return "";
}

bool
cfg_t::parallel_shard_supported()
{
    return false;
}

void *
cfg_t::parallel_shard_init_stream(int shard_index, void *worker_data,
                                   memtrace_stream_t *shard_stream)
{
    return shard_stream;
}
// result_graph
bool
cfg_t::parallel_shard_exit(void *shard_data)
{
    shard_data_t * data = reinterpret_cast<shard_data_t *>(shard_data);
    
    const std::lock_guard<std::mutex> lg(lock);
    for (const auto& bb : data->local_bbs) {
        auto iter = global_bbs.find(bb.first);
        
        if (iter == global_bbs.end()) {
            /// If does not exist - create
            global_bbs.insert(bb);
        }else {
            /// If exitst - merge
            for (const auto & e : bb.second.edges) 
                iter->second.edges.insert(e);
        }
    }   
    return true;
}

std::string
cfg_t::parallel_shard_error(void *shard_data)
{
    // Our parallel operation ignores all but one thread, so we need just
    // the one global error string.
    return error_string_;
}

bool
cfg_t::process_memref(const memref_t &memref)
{
    
    return parallel_shard_memref(serial_stream_, memref);
}

bool
cfg_t::process_new_bb(controll_flow_graph& bbs, app_pc trace_pc, app_pc head, app_pc tail) {
    // Checking that it is not the first bb.
    if (head) {
        // Checking that bb exists, otherwise create it.
        if (bbs.find(head) != bbs.end()) {
            bbs.emplace(std::make_pair(head, basic_block_t(head, tail)));
        }
        bbs[head].edges.insert(trace_pc);
    }
    return true;
}


bool
cfg_t::parallel_shard_memref(void *shard_data, const memref_t &memref)
{
    shard_data_t * shard = reinterpret_cast<shard_data_t *>(shard_data);
    
    if (memref.instr.type == TRACE_MARKER_TYPE_KERNEL_EVENT) {
        shard->is_new_bb = true;
    }
    if (!type_is_instr(memref.instr.type)) 
        return true;
    
    app_pc decode_pc = const_cast<app_pc>(memref.instr.encoding);
    const app_pc trace_pc = reinterpret_cast<app_pc>(memref.instr.addr);
    bool is_transfer_instruction = false;
    is_transfer_instruction = type_is_instr_branch(memref.instr.type);

    if (shard->is_new_bb) {
        process_new_bb(
              shard->local_bbs
            , trace_pc
            , shard->last_bb_head
            , shard->last_bb_tail
        );
        shard->is_new_bb = false;
    }
    
    if (is_transfer_instruction) {
        shard->is_new_bb = true;
    }

    /// Trying to find this instr in cache. If we haven't met it before, 
    /// then create it and put into cache and append additional info.
    auto instr_iter = shard->instr_cache.find(trace_pc);
    if (instr_iter == shard->instr_cache.end()) {
        instr_t * instr;
        instr_init(dcontext_.dcontext, instr);
        app_pc next_pc =
            decode_from_copy(dcontext_.dcontext, decode_pc, trace_pc, instr);
        shard->instr_cache.emplace(trace_pc,  instr);
        append_additional_info (instr, shard->local_bbs[shard->last_bb_head]);  
    } 

    shard->last_bb_tail = trace_pc;
    return true;
}

bool
cfg_t::print_results()
{
    std::ofstream out; 
    out.open("cfg.xml");
    out << "<CFG>\n";
    size_t id = 0;
    std::unordered_map<app_pc,size_t> ids;
    auto get_id = [&](app_pc head) {
        size_t res;
        if (ids.find(head) == ids.end()) {
            ids[head] = ++id;
        }
        res = ids[head];
        return res;
    };

    for(auto bb : global_bbs) {
        auto id = get_id(bb.first);
        out << "   <BB id=\"" << id << "\" name =\"\" startsaddr=\"" << std::hex <<  bb.second.head << "\" "
            << "endaddr =\"" << std::hex << bb.second.tail<<"\"\n";
        out << "      <instructionsCount>"<< bb.second.instruction_count<<"</instructionsCount>\n";
        out << "      <execution_count>"<< bb.second.execution_count<<"</execution_count>\n";
        out << "      <edges count = \""<< bb.second.edges.size() << "\">";
        size_t ind = 0;
        for (auto e : bb.second.edges) {
            out << get_id(e);
            if (ind != bb.second.edges.size() + 1){
                out << ",";
            }
        }
        out << "</edges>\n";
        out << "   </BB>\n";
    }
    out << "</CFG>\n";
    return true;
}
