

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>
#include "dr_api.h"
#include "cu.h"

const std::string cu_t::TOOL_NAME = "CU tool";

analysis_tool_t *
cu_tool_create(const std::string &module_file_path, uint64_t skip_refs,
                 uint64_t sim_refs, const std::string &syntax, unsigned int verbose,
                 const std::string &alt_module_dir)
{
    return new cu_t(module_file_path, skip_refs, sim_refs, syntax, verbose,
                      alt_module_dir);
}

cu_t::cu_t(const std::string &module_file_path, uint64_t skip_refs, uint64_t sim_refs,
               const std::string &syntax, unsigned int verbose,
               const std::string &alt_module_dir)
    : module_file_path_(module_file_path)
    , knob_verbose_(verbose)
    , trace_version_(-1)
    , knob_skip_refs_(skip_refs)
    , skip_refs_left_(knob_skip_refs_)
    , knob_sim_refs_(sim_refs)
    , sim_refs_left_(knob_sim_refs_)
    , knob_syntax_(syntax)
    , knob_alt_module_dir_(alt_module_dir)
    , num_disasm_instrs_(0)
    , prev_tid_(-1)
    , filetype_(-1)
    , timestamp_(0)
    , has_modules_(true)
{
}

std::string
cu_t::initialize_stream(memtrace_stream_t *serial_stream)
{
    serial_stream_ = serial_stream;
    return "cu";    
}

bool
cu_t::parallel_shard_supported()
{
    return false;
}

void *
cu_t::parallel_shard_init_stream(int shard_index, void *worker_data,
                                   memtrace_stream_t *shard_stream)
{
    return shard_stream;
}
// result_graph
bool
cu_t::parallel_shard_exit(void *shard_data)
{
    shard_data_t * data = reinterpret_cast<shard_data_t *>(shard_data);
    
    const std::lock_guard<std::mutex> lg(lock);
    for (const auto& cu : data->cus) {
        auto iter = g_cus.find(cu.first);
        
        if (iter == g_cus.end()) {
            /// If does not exist - create
            g_cus.insert(cu);
        }else {
            /// If exitst - merge
            for (const auto & e : cu.second.successors) 
                iter->second.successors.insert(e);
        }
    }   
    
    return true;
}

std::string
cu_t::parallel_shard_error(void *shard_data)
{
    // Our parallel operation ignores all but one thread, so we need just
    // the one global error string.
    return error_string_;
}

bool
cu_t::process_memref(const memref_t &memref)
{
    
    return parallel_shard_memref(serial_stream_, memref);
}

bool
cu_t::update_touched_memory_and_regs(shard_data_t * shard, instr_t * instr, size_t cu) {
    size_t m_index = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd_t opnd = instr_get_src(instr,i);
        for (int j = 0; j < opnd_num_regs_used(opnd); j++) {
            reg_id_t reg = opnd_get_reg_used(opnd, j);
            if (reg_is_gpr(reg) || reg_is_simd(reg) || opnd_is_memory_reference(opnd)) 
            {
                shard->mem_history[shard->mem_accs[m_index]] = cu;
            }else {
                shard->reg_history[reg] = cu;
            }
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t opnd = instr_get_dst(instr,i);
        if (!opnd_is_memory_reference(opnd)) 
            continue;
        for (int j = 0; j < opnd_num_regs_used(opnd); j++) {
            reg_id_t reg = opnd_get_reg_used(opnd, j);
            if (reg_is_gpr(reg) || reg_is_simd(reg)) {
                 shard->last_is_write[shard->mem_accs[m_index]] = cu;
            }
        }
    }
    return true;
}

bool
cu_t::process_old_reference(shard_data_t * shard, instr_t* instr) {
    if (instr == nullptr) 
        return true;
    
    bool create_new_cu = false;
    size_t m_index = 0;
    size_t max_cu = 0;
    
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd_t opnd = instr_get_src(instr,i);
        for (int j = 0; j < opnd_num_regs_used(opnd); j++) {
            reg_id_t reg = opnd_get_reg_used(opnd, j);
            if (reg_is_gpr(reg) || reg_is_simd(reg) || opnd_is_memory_reference(opnd)) 
            {
                bool & is_last_write = shard->last_is_write[shard->mem_accs[m_index]];
                // Appending trace reference patterns. 
                print_write_accesses(shard->read_write_access, instr, true, is_last_write);
                create_new_cu = 
                    std::max(create_new_cu, is_last_write);
                is_last_write = false;
                m_index++;
                max_cu = shard->mem_history[shard->mem_accs[m_index]];
            }else if(!create_new_cu) {
                max_cu = std::max(shard->reg_history[reg], max_cu);
            }
        }
    }
    // Updating write ref.
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd_t opnd = instr_get_dst(instr,i);
        if (!opnd_is_memory_reference(opnd)) 
            continue;
        for (int j = 0; j < opnd_num_regs_used(opnd); j++) {
            reg_id_t reg = opnd_get_reg_used(opnd, j);
            if (reg_is_gpr(reg) || reg_is_simd(reg)) {
                bool & is_last_write = shard->last_is_write[shard->mem_accs[m_index]]; 
                // Appending trace reference patterns. 
                print_write_accesses(shard->read_write_access, instr, is_last_write, true);
                is_last_write = true;
                m_index++;
            }
        }
    }
    if (create_new_cu) {
        size_t cu_ind = ++shard->cus_count;
        shard->cus.emplace(cu_ind, computation_unit_t(instr));
        shard->cus[max_cu].add_edge(cu_ind);
        max_cu = cu_ind;
    } else {
        shard->cus[max_cu].add(instr);
    }
    /// Updating reg_history and mem_history  which we touched, by new cu number.  
    update_touched_memory_and_regs(shard, instr, max_cu);

    shard->mem_accs.clear();
    
    return true;
}


bool
cu_t::parallel_shard_memref(void *shard_data, const memref_t &memref)
{
    shard_data_t * shard = reinterpret_cast<shard_data_t *>(shard_data);
   
    if(type_is_instr(memref.instr.type) || memref.data.type == TRACE_TYPE_THREAD_EXIT) {
        process_old_reference(shard,shard->current_instr);
    }

    if(type_is_data(memref.data.type)) {
        shard->mem_accs.push_back(reinterpret_cast<app_pc>(memref.data.addr));
        return true;
    }

    if (!type_is_instr(memref.instr.type)) 
        return true;
    
    app_pc decode_pc = const_cast<app_pc>(memref.instr.encoding);
    const app_pc trace_pc = reinterpret_cast<app_pc>(memref.instr.addr);
    bool is_transfer_instruction = false;
    
    auto instr_iter = shard->instr_cache.find(trace_pc);
    
    
    /// Trying to find this instr in cache. If we haven't met it before, 
    /// then create it and put into cache.
    
    instr_t * instr;
    if (instr_iter == shard->instr_cache.end()) {
        instr_init(dcontext_.dcontext, instr);
        app_pc next_pc =
            decode_from_copy(dcontext_.dcontext, decode_pc, trace_pc, instr);
        shard->instr_cache.emplace(trace_pc, instr);
    } else {
        instr = instr_iter->second;
    } 

    return true;
}

bool
cu_t::print_results()
{
    std::ofstream out; 
    out.open("cus.xml");
    out << "<CUS>\n";
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

    for(auto cu : g_cus) {
        
        out << "   <CU id=\"" << cu.first << ">\n";
        out << "      <instructions count = \""<< cu.second.instructions.size() << "\">";
        size_t ind = 0;
        for (auto i : cu.second.instructions) {
            out << std::hex << "\"" << i << "\""; 
            if (ind != cu.second.instructions.size() + 1){
                out << ",";
            }
        }
        out << "</instructions>\n";
        out << "      <successors count = \""<< cu.second.successors.size() << "\">";
        ind = 0;
        for (auto i : cu.second.successors) {
            out << std::hex << "\"" << i << "\""; 
            if (ind != cu.second.successors.size() + 1){
                out << ",";
            }
        }
        out << "</successors>\n";
        out << "      <readDataSize>"<< cu.second.readDataSize<<"</readDataSize>\n";
        out << "      <writeDataSize>"<< cu.second.writeDataSize<<"</writeDataSize>\n";
        out << "   </CU>\n";
    }
    out << "</CUS>\n";
    return true;
}
